package pt.ua.estga.mensageiro.cliente;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import pt.ua.estga.mensageiro.protocolo.Protocolo;
import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;
import pt.ua.estga.mensageiro.seguranca.EnvelopeSeguro;
import pt.ua.estga.mensageiro.seguranca.IdentidadeLocal;
import pt.ua.estga.mensageiro.seguranca.ValidacaoCertificado;

/**
 * Sessão de um cliente com o relay: ligação TLS, pedidos e receção
 * de envelopes. Usada pelo cliente de consola e pela interface gráfica,
 * para que a lógica de segurança exista num único sítio.
 */
public final class SessaoCliente implements AutoCloseable {

    /** Identidades preparadas pelo script de certificados. */
    public static final List<String> UTILIZADORES =
            List.of("cristiano", "joao");

    /** Recebe o que chega do relay sem ter sido pedido. */
    public interface Ouvinte {

        /** Só é chamado depois de verificar assinatura e decifrar. */
        void mensagemVerificada(String remetente, String texto);

        /** O remetente indicado não é fiável: o envelope falhou. */
        void mensagemRejeitada(String motivo);

        void ligacaoTerminada(String motivo);
    }

    /** O certificado do relay não foi aceite (módulo A). */
    public static final class RelayRejeitado extends IOException {
        RelayRejeitado(SSLHandshakeException causa) {
            super("Relay rejeitado: o certificado apresentado não é válido "
                    + "para esta CA ou para localhost.", causa);
        }
    }

    private final String utilizador;
    private final IdentidadeLocal identidade;
    private final SSLSocket ligacao;
    private final DataInputStream entrada;
    private final DataOutputStream saida;
    private final Ouvinte ouvinte;

    private final ArrayBlockingQueue<Protocolo.Mensagem> respostas =
            new ArrayBlockingQueue<>(16);

    private final Object pedidos = new Object();

    // Limitamos as mensagens que ficam à espera de verificação.
    // Acima do limite de 200 mensagens por caixa no relay:
    // um levantamento completo não pode rejeitar entregas.
    private final ThreadPoolExecutor entregas = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(256),
            Thread.ofPlatform().daemon().name("entregas").factory(),
            new ThreadPoolExecutor.AbortPolicy());

    private final Thread leitor;

    private volatile boolean ativa = true;

    private SessaoCliente(
            String utilizador,
            IdentidadeLocal identidade,
            SSLSocket ligacao,
            Ouvinte ouvinte) throws IOException {

        this.utilizador = utilizador;
        this.identidade = identidade;
        this.ligacao = ligacao;
        this.ouvinte = ouvinte;

        entrada = new DataInputStream(ligacao.getInputStream());
        saida = new DataOutputStream(ligacao.getOutputStream());

        leitor = Thread.ofPlatform().daemon().name("leitor").start(this::ler);
    }

    /**
     * Carrega a identidade, valida-a e abre a ligação TLS ao relay.
     * As palavras-passe são apagadas da memória antes de retornar.
     */
    public static SessaoCliente ligar(
            String utilizador,
            char[] passeIdentidade,
            char[] passeConfianca,
            Ouvinte ouvinte) throws Exception {

        if (!UTILIZADORES.contains(utilizador)) {
            throw new IllegalArgumentException(
                    "Utilizador desconhecido: " + utilizador);
        }

        SSLContext contexto;
        IdentidadeLocal identidade;

        try {
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
            Arrays.fill(passeIdentidade, '\0');
            Arrays.fill(passeConfianca, '\0');
        }

        SSLSocket ligacao = (SSLSocket)
                contexto.getSocketFactory().createSocket();

        try {
            ligacao.setEnabledProtocols(new String[] {"TLSv1.3"});

            SSLParameters parametros = ligacao.getSSLParameters();
            parametros.setEndpointIdentificationAlgorithm("HTTPS");
            ligacao.setSSLParameters(parametros);

            ligacao.connect(new InetSocketAddress("localhost", 8443), 5_000);
            ligacao.setSoTimeout(10_000);

            try {
                ligacao.startHandshake();
            } catch (SSLHandshakeException falhaTLS) {
                // Demonstração do módulo A: relay falso ou não confiável.
                throw new RelayRejeitado(falhaTLS);
            }

            // A partir daqui podemos ficar à espera de mensagens.
            ligacao.setSoTimeout(0);

            return new SessaoCliente(utilizador, identidade, ligacao, ouvinte);

        } catch (Exception erro) {
            ligacao.close();
            throw erro;
        }
    }

    public String utilizador() {
        return utilizador;
    }

    public String protocolo() {
        return ligacao.getSession().getProtocol();
    }

    public boolean ativa() {
        return ativa;
    }

    /** Associa esta sessão à identidade do certificado TLS. */
    public String registar() throws Exception {
        Protocolo.Mensagem resposta = pedir(Protocolo.REGISTAR, new byte[0]);
        exigirSucesso(resposta);
        return texto(resposta);
    }

    /**
     * Pede as mensagens guardadas. As entregas chegam antes da resposta
     * e seguem o caminho normal de verificação, até ao Ouvinte.
     */
    public String levantar() throws Exception {
        Protocolo.Mensagem resposta = pedir(Protocolo.LEVANTAR, new byte[0]);
        exigirSucesso(resposta);
        return texto(resposta);
    }

    /** Obtém o certificado de um utilizador e valida-o com a CA. */
    public X509Certificate procurar(String nome) throws Exception {
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
            throw new IllegalStateException("Resposta inesperada à procura.");
        }

        return ValidacaoCertificado.validarUtilizador(resposta.dados(), nome);
    }

    /** Valida o destinatário, cria o envelope e envia-o. */
    public String enviar(String destinatario, String mensagem)
            throws Exception {

        X509Certificate certificado = procurar(destinatario);

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
        return texto(resposta);
    }

    @Override
    public void close() {
        terminarLigacao();
        leitor.interrupt();
        entregas.shutdownNow();
    }

    private void ler() {
        try {
            while (ativa) {
                Protocolo.Mensagem mensagem = Protocolo.receber(entrada);

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
                // Um fecho normal do relay chega como EOF, sem mensagem.
                ouvinte.ligacaoTerminada(erro instanceof java.io.EOFException
                        || erro.getMessage() == null
                                ? "o relay fechou a ligação."
                                : erro.getMessage());
            }
            terminarLigacao();
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
                terminarLigacao();
                throw new IllegalStateException(
                        "O relay não respondeu a tempo. Reinicia o cliente.");
            }

            return resposta;
        }
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

            // Só entregamos o conteúdo depois de verificar o envelope.
            ouvinte.mensagemVerificada(
                    remetente, new String(mensagem, StandardCharsets.UTF_8));

        } catch (Exception erro) {
            ouvinte.mensagemRejeitada(erro.getMessage());
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
        } catch (IOException ignorado) {
            // A ligação já está a terminar.
        }
    }

    private static String texto(Protocolo.Mensagem mensagem) {
        return new String(mensagem.dados(), StandardCharsets.UTF_8);
    }
}
