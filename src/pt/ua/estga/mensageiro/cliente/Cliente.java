package pt.ua.estga.mensageiro.cliente;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import pt.ua.estga.mensageiro.protocolo.Protocolo;
import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;
import pt.ua.estga.mensageiro.seguranca.EnvelopeSeguro;
import pt.ua.estga.mensageiro.seguranca.IdentidadeLocal;
import pt.ua.estga.mensageiro.seguranca.ValidacaoCertificado;

public final class Cliente {

    private final String utilizador;
    private final IdentidadeLocal identidade;
    private final DataInputStream entrada;
    private final DataOutputStream saida;
        private final SSLSocket ligacao;

    private final ArrayBlockingQueue<Protocolo.Mensagem> respostas =
            new ArrayBlockingQueue<>(16);

    private final Object pedidos = new Object();

    private volatile boolean ativa = true;

    private Cliente(
            String utilizador,
            IdentidadeLocal identidade,
            SSLSocket ligacao) throws Exception {

        this.utilizador = utilizador;
        this.identidade = identidade;
        this.ligacao = ligacao;
        
        entrada = new DataInputStream(ligacao.getInputStream());
        saida = new DataOutputStream(ligacao.getOutputStream());

    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1
                || !(args[0].equals("joao")
                || args[0].equals("cristiano"))) {
            System.err.println("Utilização: Cliente <joao|cristiano>");
            return;
        }

        String utilizador = args[0];
        Console consola = System.console();

        if (consola == null) {
            throw new IllegalStateException(
                    "Executa o cliente num Terminal interativo.");
        }

        char[] passeIdentidade = consola.readPassword(
                "Palavra-passe da identidade de %s: ", utilizador);
        char[] passeConfianca = consola.readPassword(
                "Palavra-passe do ficheiro de confiança: ");

        SSLContext contexto;
        IdentidadeLocal identidade;

        try {
            if (passeIdentidade == null || passeConfianca == null) {
                throw new IllegalStateException("Leitura cancelada.");
            }

            Path ficheiro = Path.of(
                    "certificados/identidades/" + utilizador + ".p12");

            contexto = ConfiguracaoTLS.criarContexto(
                    ficheiro,
                    passeIdentidade,
                    Path.of("certificados/confianca/confianca.p12"),
                    passeConfianca);

            identidade = IdentidadeLocal.carregar(
                    ficheiro, passeIdentidade, utilizador);

            // Confirmamos também a identidade carregada localmente.
            ValidacaoCertificado.validarUtilizador(
                    identidade.certificado().getEncoded(), utilizador);
        } finally {
            if (passeIdentidade != null) {
                Arrays.fill(passeIdentidade, '\0');
            }
            if (passeConfianca != null) {
                Arrays.fill(passeConfianca, '\0');
            }
        }

        try (SSLSocket ligacao = (SSLSocket)
                contexto.getSocketFactory().createSocket()) {

            ligacao.setEnabledProtocols(new String[] {"TLSv1.3"});

            SSLParameters parametros = ligacao.getSSLParameters();
            parametros.setEndpointIdentificationAlgorithm("HTTPS");
            ligacao.setSSLParameters(parametros);

            ligacao.connect(new InetSocketAddress("localhost", 8443), 5_000);
            ligacao.setSoTimeout(10_000);
            ligacao.startHandshake();

            System.out.println("Ligação TLS estabelecida: "
                    + ligacao.getSession().getProtocol());

            // A partir daqui podemos ficar à espera de mensagens.
            ligacao.setSoTimeout(0);

            Cliente cliente = new Cliente(
                    utilizador, identidade, ligacao);

            try {
                cliente.executar(consola);
            } finally {
                cliente.ativa = false;
            }
        }
    }

    private void executar(Console consola) throws Exception {
        // Limitamos as mensagens que ficam à espera de verificação.
        var entregas = new java.util.concurrent.ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(32),
                Thread.ofVirtual().factory(),
                new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());

        Thread leitor = Thread.ofVirtual().start(() -> {
            try {
                while (ativa) {
                    Protocolo.Mensagem mensagem =
                            Protocolo.receber(entrada);

                    if (mensagem.tipo() == Protocolo.ENTREGA) {
                        if (entregas.isShutdown()) {
                            break;
                        }

                        entregas.submit(() -> receberEnvelope(mensagem));
                    } else if (!respostas.offer(mensagem)) {
                        throw new IllegalStateException(
                                "Demasiadas respostas pendentes.");
                    }
                }
            } catch (Exception erro) {
                if (ativa) {
                    System.err.println(
                            "\nLigação terminada: " + erro.getMessage());
                }
                terminarLigacao();  
            }
        });

        try {
            Protocolo.Mensagem registo =
                    pedir(Protocolo.REGISTAR, new byte[0]);

            exigirSucesso(registo);
            System.out.println(texto(registo));

            System.out.println(
                    "Comandos: procurar <nome>, enviar <nome>, sair");

            while (ativa) {
                String comando = consola.readLine("> ");

                if (comando == null || comando.equals("sair")) {
                    break;
                }

                if (!ativa) {
                    break;
                }

                try {
                    if (comando.startsWith("procurar ")) {
                        String nome = comando.substring(9).trim();
                        X509Certificate certificado = procurar(nome);

                        System.out.println("Certificado validado: "
                                + certificado.getSubjectX500Principal()
                                        .getName());

                    } else if (comando.startsWith("enviar ")) {
                        String nome = comando.substring(7).trim();
                        X509Certificate certificado = procurar(nome);
                        String mensagem = consola.readLine("Mensagem: ");

                        if (mensagem != null && ativa) {
                            enviarEnvelope(nome, mensagem, certificado);
                        }

                    } else {
                        System.out.println(
                                "Usa: procurar <nome>, enviar <nome> ou sair");
                    }
                } catch (Exception erro) {
                    System.err.println(
                            "Operação recusada: " + erro.getMessage());
                }
            }
        } finally {
            terminarLigacao();
            leitor.interrupt();
            entregas.shutdownNow();
        }
    }

    private Protocolo.Mensagem pedir(int tipo, byte[] dados)
            throws Exception {

        // Só há um pedido em espera de resposta de cada vez.
        synchronized (pedidos) {
            if (!ativa) {
                throw new IllegalStateException("A ligação está fechada.");
            }

            synchronized (saida) {
                Protocolo.enviar(saida, tipo, dados);
            }

            Protocolo.Mensagem resposta =
                    respostas.poll(15, TimeUnit.SECONDS);

            if (resposta == null) {
                // Não reutilizamos uma sessão com respostas incertas.
                ativa = false;
                throw new IllegalStateException(
                        "O relay não respondeu a tempo. Reinicia o cliente.");
            }

            return resposta;
        }
    }

    private X509Certificate procurar(String nome) throws Exception {
        if (!nome.matches("[a-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException("Identificador inválido.");
        }

        Protocolo.Mensagem resposta = pedir(
                Protocolo.PROCURAR,
                nome.getBytes(StandardCharsets.UTF_8));

        if (resposta.tipo() == Protocolo.ERRO) {
            throw new IllegalStateException(texto(resposta));
        }

        if (resposta.tipo() != Protocolo.CERTIFICADO) {
            throw new IllegalStateException(
                    "Resposta inesperada à procura.");
        }

        return ValidacaoCertificado.validarUtilizador(
                resposta.dados(), nome);
    }

    private void enviarEnvelope(
            String destinatario,
            String mensagem,
            X509Certificate certificado) throws Exception {

        byte[] envelope = EnvelopeSeguro.criar(
                utilizador,
                destinatario,
                mensagem.getBytes(StandardCharsets.UTF_8),
                identidade.chavePrivada(),
                certificado.getPublicKey());

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (DataOutputStream pedido = new DataOutputStream(bytes)) {
            pedido.writeUTF(destinatario);
            pedido.writeInt(envelope.length);
            pedido.write(envelope);
        }

        Protocolo.Mensagem resposta =
                pedir(Protocolo.ENVIAR, bytes.toByteArray());

        exigirSucesso(resposta);
        System.out.println(texto(resposta));
    }

    private void receberEnvelope(Protocolo.Mensagem entrega) {
        try {
            String remetente;
            byte[] envelope;

            try (DataInputStream dados = new DataInputStream(
                    new ByteArrayInputStream(entrega.dados()))) {
                remetente = dados.readUTF();
                int tamanho = dados.readInt();

                if (tamanho < 1 || tamanho > 60 * 1024) {
                    throw new IllegalArgumentException(
                            "Tamanho de envelope inválido.");
                }

                envelope = new byte[tamanho];
                dados.readFully(envelope);

                if (dados.read() != -1) {
                    throw new IllegalArgumentException(
                            "Dados adicionais na entrega.");
                }
            }

            X509Certificate certificado = procurar(remetente);

            byte[] mensagem = EnvelopeSeguro.abrir(
                    envelope,
                    remetente,
                    utilizador,
                    certificado.getPublicKey(),
                    identidade.chavePrivada());

            // Só mostramos o conteúdo depois de verificar o envelope.
            System.out.println("\nMensagem verificada de " + remetente + ": "
                    + new String(mensagem, StandardCharsets.UTF_8));

        } catch (Exception erro) {
            System.err.println(
                    "\nMensagem rejeitada: " + erro.getMessage());
        }
    }

    private static void exigirSucesso(Protocolo.Mensagem resposta) {
        if (resposta.tipo() != Protocolo.SUCESSO) {
            throw new IllegalStateException(
                    "Pedido recusado: " + texto(resposta));
        }
    }

    private void terminarLigacao() {
        ativa = false;

        try {
            ligacao.close();
        } catch (java.io.IOException ignorado) {
            // A ligação já está a terminar.
        }
    }

    private static String texto(Protocolo.Mensagem mensagem) {
        return new String(mensagem.dados(), StandardCharsets.UTF_8);
    }
}
