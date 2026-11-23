package pt.ua.estga.mensageiro.relay;

import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import pt.ua.estga.mensageiro.protocolo.Protocolo;
import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;
import pt.ua.estga.mensageiro.seguranca.IdentidadeLocal;

public final class Relay {

    private static final Path DADOS = Path.of("dados-relay");
    private static final Path DIRETORIO = DADOS.resolve("utilizadores");

    // Intervalo máximo entre pontos de controlo, mesmo com pouca atividade.
    private static final long SEGUNDOS_ENTRE_PONTOS = 60;

    private static final ConcurrentHashMap<String, X509Certificate>
            utilizadores = new ConcurrentHashMap<>();

    private static SessoesRelay sessoes;
    private static RegistoAuditoria auditoria;

    public static void main(String[] args) throws Exception {
        Console consola = System.console();

        if (consola == null) {
            throw new IllegalStateException(
                    "Executa o relay num Terminal interativo.");
        }

        char[] passeIdentidade = consola.readPassword(
                "Palavra-passe da identidade do relay: ");
        char[] passeConfianca = consola.readPassword(
                "Palavra-passe do ficheiro de confiança: ");

        SSLContext contexto;
        IdentidadeLocal identidadeRelay;

        try {
            if (passeIdentidade == null || passeConfianca == null) {
                throw new IllegalStateException("Leitura cancelada.");
            }

            Path ficheiroIdentidade =
                    Path.of("certificados/identidades/relay.p12");

            contexto = ConfiguracaoTLS.criarContexto(
                    ficheiroIdentidade,
                    passeIdentidade,
                    Path.of("certificados/confianca/confianca.p12"),
                    passeConfianca);

            // A mesma chave assina os pontos de controlo da auditoria.
            identidadeRelay = IdentidadeLocal.carregar(
                    ficheiroIdentidade, passeIdentidade, "relay");
        } catch (ConfiguracaoTLS.PalavraPasseIncorreta erro) {
            System.err.println(erro.getMessage());
            System.exit(1);
            return;
        } finally {
            if (passeIdentidade != null) {
                Arrays.fill(passeIdentidade, '\0');
            }
            if (passeConfianca != null) {
                Arrays.fill(passeConfianca, '\0');
            }
        }

        carregarDiretorio();

        sessoes = new SessoesRelay(
                new ArmazemMensagens(DADOS.resolve("caixas")));
        auditoria = new RegistoAuditoria(
                DADOS.resolve("auditoria.log"),
                identidadeRelay.chavePrivada());

        auditoria.registar("ARRANQUE");

        ScheduledExecutorService relogio =
                Executors.newSingleThreadScheduledExecutor();

        relogio.scheduleAtFixedRate(() -> {
            try {
                auditoria.pontoDeControlo();
            } catch (Exception erro) {
                System.err.println("Ponto de controlo falhou: "
                        + erro.getMessage());
            }
        }, SEGUNDOS_ENTRE_PONTOS, SEGUNDOS_ENTRE_PONTOS, TimeUnit.SECONDS);

        // Ctrl+C: fecha a cadeia com um último ponto de controlo.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            relogio.shutdownNow();
            auditoria.registar("PARAGEM");
            try {
                auditoria.close();
            } catch (IOException ignorado) {
                // Estamos a terminar.
            }
        }));

        try (SSLServerSocket servidor = (SSLServerSocket)
                    contexto.getServerSocketFactory().createServerSocket(
                            8443, 50, InetAddress.getLoopbackAddress());
             ExecutorService tarefas =
                    Executors.newVirtualThreadPerTaskExecutor()) {

            servidor.setEnabledProtocols(new String[] {"TLSv1.3"});
            servidor.setNeedClientAuth(true);

            System.out.println(
                    "Relay à escuta na porta 8443, apenas neste computador.");

            while (true) {
                SSLSocket cliente = (SSLSocket) servidor.accept();
                tarefas.submit(() -> atender(cliente));
            }
        }
    }

    private static void atender(SSLSocket cliente) {

        String identidadeSessao = null;
        DataOutputStream saidaSessao = null;

        try (cliente) {
            cliente.setSoTimeout(10_000);

            try {
                cliente.startHandshake();
            } catch (SSLHandshakeException falhaTLS) {
                // Sem identidade autenticada: não há nome a registar.
                auditoria.registar("FALHA", "tls");
                throw falhaTLS;
            }

            X509Certificate certificado = (X509Certificate)
                    cliente.getSession().getPeerCertificates()[0];

            String identidade = obterIdentidade(certificado);

            System.out.println("Ligação TLS autenticada: " + identidade);

            // Permitimos até 30 minutos sem receber dados do cliente.
            cliente.setSoTimeout(30 * 60 * 1000);

            DataInputStream entrada =
                    new DataInputStream(cliente.getInputStream());
            DataOutputStream saida =
                    new DataOutputStream(cliente.getOutputStream());

            identidadeSessao = identidade;
            saidaSessao = saida;

            boolean registado = false;

            while (true) {
                Protocolo.Mensagem pedido = Protocolo.receber(entrada);

                switch (pedido.tipo()) {
                    case Protocolo.REGISTAR -> {
                        if (pedido.dados().length != 0) {
                            responderTexto(saida, Protocolo.ERRO,
                                    "O registo não aceita dados adicionais.");
                            continue;
                        }

                        // Um certificado diferente não substitui o anterior.
                        X509Certificate anterior = utilizadores.putIfAbsent(
                                identidade, certificado);

                        if (anterior != null
                                && !anterior.equals(certificado)) {
                            auditoria.registar("FALHA", "certificado",
                                    identidade);
                            responderTexto(saida, Protocolo.ERRO,
                                    "Identidade associada a outro certificado.");
                            continue;
                        }

                        if (!registado && !sessoes.adicionar(identidade, saida)) {
                            responderTexto(saida, Protocolo.ERRO,
                                    "Já existe uma ligação para este utilizador.");
                            continue;
                        }

                        if (anterior == null) {
                            guardarNoDiretorio(identidade, certificado);
                            auditoria.registar("REGISTO", identidade);
                        }

                        registado = true;
                        responderTexto(saida, Protocolo.SUCESSO,
                                "Registo confirmado: " + identidade);

                        System.out.println("Registo confirmado: " + identidade);
                    }

                    case Protocolo.PROCURAR -> {
                        if (!registado) {
                            responderTexto(saida, Protocolo.ERRO,
                                    "É necessário registar esta ligação.");
                            continue;
                        }

                        String procurado = new String(
                                pedido.dados(), StandardCharsets.UTF_8);

                        if (!identificadorValido(procurado)) {
                            responderTexto(saida, Protocolo.ERRO,
                                    "Identificador inválido.");
                            continue;
                        }

                        X509Certificate encontrado =
                                utilizadores.get(procurado);

                        if (encontrado == null) {
                            responderTexto(saida, Protocolo.ERRO,
                                    "Utilizador não encontrado.");
                        } else {
                            synchronized (saida) {
                                Protocolo.enviar(saida, Protocolo.CERTIFICADO,
                                        encontrado.getEncoded());
                            }
                        }
                    }

                    case Protocolo.ENVIAR -> {
                        if (!registado) {
                            responderTexto(saida, Protocolo.ERRO,
                                    "É necessário registar esta ligação.");
                            continue;
                        }

                        try {
                            SessoesRelay.PedidoEnvio envio =
                                    SessoesRelay.interpretar(
                                            identidade, pedido.dados());

                            SessoesRelay.Resultado resultado =
                                    sessoes.encaminhar(envio,
                                            utilizadores::containsKey);

                            auditoria.registar("ENVIO", identidade,
                                    envio.destinatario(),
                                    resultado.name());

                            responderTexto(saida, Protocolo.SUCESSO,
                                    resultado == SessoesRelay.Resultado.ENTREGUE
                                            ? "Envelope encaminhado."
                                            : "Destinatário desligado: "
                                              + "envelope guardado no relay.");
                        } catch (IOException erroEnvio) {
                            auditoria.registar("FALHA", "envio", identidade);
                            responderTexto(saida, Protocolo.ERRO,
                                    "Não foi possível encaminhar o envelope: "
                                    + erroEnvio.getMessage());
                        }
                    }

                    case Protocolo.LEVANTAR -> {
                        // Controlo de acesso: só a caixa da identidade
                        // autenticada por TLS; o pedido não leva nome.
                        if (!registado || pedido.dados().length != 0) {
                            auditoria.registar("FALHA", "levantamento",
                                    identidade);
                            responderTexto(saida, Protocolo.ERRO,
                                    "Pedido de levantamento recusado.");
                            continue;
                        }

                        int entregues = sessoes.levantar(identidade, saida);

                        auditoria.registar("LEVANTAMENTO", identidade,
                                Integer.toString(entregues));

                        responderTexto(saida, Protocolo.SUCESSO,
                                "Mensagens levantadas: " + entregues);
                    }

                    default -> responderTexto(saida, Protocolo.ERRO,
                            "Tipo de pedido desconhecido.");
                }
            }
        } catch (EOFException fim) {
            // O cliente terminou a ligação.
        } catch (Exception erro) {
            System.err.println(
                    "Ligação rejeitada ou interrompida: "
                    + erro.getClass().getSimpleName()
                    + " — " + erro.getMessage());
        } finally {
            if (identidadeSessao != null && saidaSessao != null) {
                sessoes.remover(identidadeSessao, saidaSessao);
            }
        }
    }

    /** Recupera o diretório de utilizadores depois de um reinício. */
    private static void carregarDiretorio() throws Exception {
        Files.createDirectories(DIRETORIO);
        CertificateFactory fabrica = CertificateFactory.getInstance("X.509");

        try (Stream<Path> ficheiros = Files.list(DIRETORIO)) {
            for (Path ficheiro : ficheiros
                    .filter(f -> f.toString().endsWith(".cer")).toList()) {

                X509Certificate certificado = (X509Certificate)
                        fabrica.generateCertificate(new ByteArrayInputStream(
                                Files.readAllBytes(ficheiro)));

                utilizadores.put(obterIdentidade(certificado), certificado);
            }
        }

        System.out.println("Utilizadores conhecidos: " + utilizadores.size());
    }

    private static void guardarNoDiretorio(
            String identidade, X509Certificate certificado) throws Exception {
        Path temporario = DIRETORIO.resolve(identidade + ".tmp");
        Files.write(temporario, certificado.getEncoded());
        Files.move(temporario, DIRETORIO.resolve(identidade + ".cer"),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
    }

    private static String obterIdentidade(X509Certificate certificado)
            throws Exception {

        LdapName nome = new LdapName(
                certificado.getSubjectX500Principal().getName());

        String identidade = null;

        for (Rdn atributo : nome.getRdns()) {
            // Nesta versão só aceitamos atributos simples.
            if (atributo.size() != 1) {
                throw new IllegalArgumentException(
                        "Nome do certificado não suportado.");
            }

            if ("CN".equalsIgnoreCase(atributo.getType())) {
                if (identidade != null) {
                    throw new IllegalArgumentException(
                            "Certificado com vários identificadores CN.");
                }
                identidade = atributo.getValue().toString();
            }
        }

        if (!identificadorValido(identidade)) {
            throw new IllegalArgumentException(
                    "Identidade inválida no certificado.");
        }

        return identidade;
    }

    private static boolean identificadorValido(String valor) {
        return valor != null && valor.matches("[a-z0-9_-]{1,32}");
    }

    private static void responderTexto(
            DataOutputStream saida, int tipo, String texto)
            throws Exception {

        synchronized (saida) {
            Protocolo.enviar(saida, tipo,
                    texto.getBytes(StandardCharsets.UTF_8));
        }
    }
}
