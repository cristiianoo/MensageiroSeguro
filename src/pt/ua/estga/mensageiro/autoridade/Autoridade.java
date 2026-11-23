package pt.ua.estga.mensageiro.autoridade;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import pt.ua.estga.mensageiro.protocolo.Protocolo;
import pt.ua.estga.mensageiro.seguranca.ArmazemChaves;
import pt.ua.estga.mensageiro.seguranca.Caminhos;
import pt.ua.estga.mensageiro.seguranca.CertificadoX509;
import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;
import pt.ua.estga.mensageiro.seguranca.IdentidadeLocal;

/**
 * Autoridade de registo: a única parte do sistema com a chave da CA.
 *
 * No primeiro arranque cria a CA, a sua própria identidade TLS e a do
 * relay. Depois emite certificados de utilizador a quem pedir um nome
 * livre e provar que tem a chave privada correspondente.
 *
 * Está separada do relay de propósito: quem controla o relay não
 * consegue emitir um certificado falso para se fazer passar por alguém.
 */
public final class Autoridade {

    private static final Duration VALIDADE_CA = Duration.ofDays(3650);
    private static final Duration VALIDADE = Duration.ofDays(365);
    private static final int MAXIMO_CONTAS = 10_000;

    private final IdentidadeLocal ca;

    private Autoridade(IdentidadeLocal ca) {
        this.ca = ca;
    }

    public static void main(String[] args) throws Exception {
        try {
            if (!preparado()) {
                preparar();
            }
        } catch (IllegalStateException pastaInvalida) {
            System.err.println(pastaInvalida.getMessage());
            System.exit(1);
        }

        IdentidadeLocal ca = IdentidadeLocal.carregar(Caminhos.CA,
                ArmazemChaves.lerSegredo(Caminhos.CA_SEGREDO), "ca");
        Autoridade autoridade = new Autoridade(ca);

        char[] segredo = ArmazemChaves.lerSegredo(Caminhos.AUTORIDADE_SEGREDO);
        SSLContext contexto =
                ConfiguracaoTLS.criarContexto(Caminhos.AUTORIDADE, segredo);
        java.util.Arrays.fill(segredo, '\0');

        Files.createDirectories(Caminhos.EMITIDOS);

        try (SSLServerSocket servidor = (SSLServerSocket)
                    contexto.getServerSocketFactory().createServerSocket(
                            Caminhos.PORTA_AUTORIDADE, 50,
                            InetAddress.getLoopbackAddress());
             ExecutorService tarefas =
                    Executors.newVirtualThreadPerTaskExecutor()) {

            servidor.setEnabledProtocols(new String[] {"TLSv1.3"});
            // Quem cria conta ainda não tem certificado: só o servidor
            // se autentica nesta ligação.
            servidor.setNeedClientAuth(false);

            System.out.println("Autoridade à escuta na porta "
                    + Caminhos.PORTA_AUTORIDADE + ", apenas neste computador. "
                    + "Contas emitidas: " + contarEmitidos());

            while (true) {
                SSLSocket cliente = (SSLSocket) servidor.accept();
                tarefas.submit(() -> autoridade.atender(cliente));
            }
        }
    }

    /** Um pedido por ligação: criar conta. */
    private void atender(SSLSocket cliente) {
        try (cliente) {
            cliente.setSoTimeout(10_000);
            cliente.startHandshake();

            DataInputStream entrada =
                    new DataInputStream(cliente.getInputStream());
            DataOutputStream saida =
                    new DataOutputStream(cliente.getOutputStream());

            Protocolo.Mensagem pedido = Protocolo.receber(entrada);

            if (pedido.tipo() != Protocolo.CRIAR_CONTA) {
                responder(saida, Protocolo.ERRO, "Pedido desconhecido.");
                return;
            }

            try {
                X509Certificate certificado =
                        emitir(PedidoConta.descodificar(pedido.dados()));

                Protocolo.enviar(saida, Protocolo.CERTIFICADO,
                        certificado.getEncoded());
            } catch (FileAlreadyExistsException ocupado) {
                responder(saida, Protocolo.ERRO, "Esse nome já está em uso.");
            } catch (Exception recusado) {
                System.out.println("Pedido recusado: " + recusado.getMessage());
                responder(saida, Protocolo.ERRO, recusado.getMessage());
            }
        } catch (EOFException fim) {
            // O cliente desistiu.
        } catch (Exception erro) {
            System.err.println("Ligação interrompida: "
                    + erro.getClass().getSimpleName() + " — "
                    + erro.getMessage());
        }
    }

    /**
     * Valida o pedido e emite o certificado. Sincronizado: dois pedidos
     * para o mesmo nome ao mesmo tempo não podem ambos ganhar.
     */
    synchronized X509Certificate emitir(PedidoConta pedido) throws Exception {
        PublicKey chave = pedido.validar();

        if (contarEmitidos() >= MAXIMO_CONTAS) {
            throw new IllegalStateException("Limite de contas atingido.");
        }

        X509Certificate certificado = CertificadoX509.emitir(
                ca.certificado(), ca.chavePrivada(), chave, pedido.nome(),
                CertificadoX509.Tipo.CLIENTE, VALIDADE);

        // CREATE_NEW falha se o nome já existir: o primeiro fica com ele.
        Files.write(Caminhos.EMITIDOS.resolve(pedido.nome() + ".cer"),
                certificado.getEncoded(), StandardOpenOption.CREATE_NEW);

        System.out.println("Conta criada: " + pedido.nome());
        return certificado;
    }

    private static long contarEmitidos() throws IOException {
        try (Stream<Path> ficheiros = Files.list(Caminhos.EMITIDOS)) {
            return ficheiros.count();
        }
    }

    private static void responder(DataOutputStream saida, int tipo,
            String texto) throws IOException {
        Protocolo.enviar(saida, tipo, texto.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------
    // Primeiro arranque
    // ------------------------------------------------------------------

    private static boolean preparado() throws IOException {
        Path[] ficheiros = {Caminhos.CA, Caminhos.CA_SEGREDO,
                Caminhos.AUTORIDADE, Caminhos.AUTORIDADE_SEGREDO,
                Caminhos.RELAY, Caminhos.RELAY_SEGREDO, Caminhos.CA_PUBLICO};

        int existentes = 0;
        for (Path ficheiro : ficheiros) {
            if (Files.exists(ficheiro)) {
                existentes++;
            }
        }

        if (existentes == ficheiros.length) {
            return true;
        }

        if (existentes > 0 || Files.exists(Caminhos.RAIZ.resolve("confianca"))) {
            throw new IllegalStateException("A pasta " + Caminhos.RAIZ
                    + " está incompleta ou foi criada pelo script antigo. "
                    + "Move-a (mv certificados certificados-antigos) e "
                    + "arranca de novo: a Autoridade cria uma nova.");
        }
        return false;
    }

    private static void preparar() throws Exception {
        System.out.println("Primeiro arranque: a criar a CA e as "
                + "identidades da Autoridade e do relay…");

        KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
        gerador.initialize(3072);

        // CA
        KeyPair chavesCA = gerador.generateKeyPair();
        X509Certificate ca = CertificadoX509.criarCA(
                chavesCA, "CA Grupo 09", VALIDADE_CA);
        ArmazemChaves.guardarIdentidade(Caminhos.CA, "ca",
                chavesCA.getPrivate(),
                ArmazemChaves.criarSegredo(Caminhos.CA_SEGREDO), ca);
        ArmazemChaves.escreverPublico(Caminhos.CA_PUBLICO,
                CertificadoX509.pem(ca));

        // Identidade TLS da própria Autoridade
        KeyPair chavesAutoridade = gerador.generateKeyPair();
        X509Certificate autoridade = CertificadoX509.emitir(ca,
                chavesCA.getPrivate(), chavesAutoridade.getPublic(),
                "localhost", CertificadoX509.Tipo.SERVIDOR, VALIDADE);
        ArmazemChaves.guardarIdentidade(Caminhos.AUTORIDADE, "autoridade",
                chavesAutoridade.getPrivate(),
                ArmazemChaves.criarSegredo(Caminhos.AUTORIDADE_SEGREDO),
                autoridade, ca);

        // Identidade do relay: TLS e assinatura dos pontos de controlo.
        KeyPair chavesRelay = gerador.generateKeyPair();
        X509Certificate relay = CertificadoX509.emitir(ca,
                chavesCA.getPrivate(), chavesRelay.getPublic(),
                "localhost", CertificadoX509.Tipo.SERVIDOR, VALIDADE);
        ArmazemChaves.guardarIdentidade(Caminhos.RELAY, "relay",
                chavesRelay.getPrivate(),
                ArmazemChaves.criarSegredo(Caminhos.RELAY_SEGREDO),
                relay, ca);
        ArmazemChaves.escreverPublico(Caminhos.RELAY_PUBLICO,
                CertificadoX509.pem(relay));

        System.out.println("Preparação concluída. Os segredos dos servidores "
                + "estão em " + Caminhos.RAIZ + " (só legíveis pelo dono).");
    }
}
