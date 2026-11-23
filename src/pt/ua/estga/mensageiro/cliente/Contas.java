package pt.ua.estga.mensageiro.cliente;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import pt.ua.estga.mensageiro.autoridade.PedidoConta;
import pt.ua.estga.mensageiro.protocolo.Protocolo;
import pt.ua.estga.mensageiro.seguranca.ArmazemChaves;
import pt.ua.estga.mensageiro.seguranca.Caminhos;
import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;
import pt.ua.estga.mensageiro.seguranca.ValidacaoCertificado;

/** Contas guardadas neste computador e criação de contas novas. */
public final class Contas {

    public static final int MINIMO_PALAVRA_PASSE = 8;

    private Contas() {
    }

    public static boolean existe(String nome) {
        return Files.exists(Caminhos.conta(nome));
    }

    /**
     * Cria uma conta nova:
     * 1. gera o par de chaves aqui (a chave privada nunca sai daqui);
     * 2. pede à Autoridade um certificado, com prova de posse;
     * 3. confirma que o certificado é da CA, para este nome e esta chave;
     * 4. guarda chave e certificado num PKCS12 cifrado com a palavra-passe.
     *
     * A palavra-passe não é enviada a ninguém.
     */
    public static void criar(String nome, char[] palavraPasse)
            throws Exception {

        PedidoConta.validarNome(nome);

        if (palavraPasse.length < MINIMO_PALAVRA_PASSE) {
            throw new IllegalArgumentException("A palavra-passe tem de ter "
                    + "pelo menos " + MINIMO_PALAVRA_PASSE + " caracteres.");
        }

        if (existe(nome)) {
            throw new IllegalStateException(
                    "Já existe a conta " + nome + " neste computador.");
        }

        KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
        gerador.initialize(3072);
        KeyPair chaves = gerador.generateKeyPair();

        byte[] resposta = pedirCertificado(PedidoConta.criar(nome, chaves));

        // Não confiamos cegamente na resposta: tem de ser um certificado
        // de utilizador da nossa CA, com o nome pedido e a nossa chave.
        X509Certificate certificado =
                ValidacaoCertificado.validarUtilizador(resposta, nome);

        if (!certificado.getPublicKey().equals(chaves.getPublic())) {
            throw new SecurityException(
                    "O certificado recebido não é para a chave gerada.");
        }

        ArmazemChaves.guardarIdentidade(Caminhos.conta(nome), nome,
                chaves.getPrivate(), palavraPasse,
                certificado, ConfiguracaoTLS.lerCA());
    }

    private static byte[] pedirCertificado(PedidoConta pedido)
            throws Exception {

        try (SSLSocket ligacao = (SSLSocket) ConfiguracaoTLS
                .criarContextoSemIdentidade().getSocketFactory()
                .createSocket()) {

            ligacao.setEnabledProtocols(new String[] {"TLSv1.3"});

            // Confirmamos que falamos com um servidor da nossa CA.
            SSLParameters parametros = ligacao.getSSLParameters();
            parametros.setEndpointIdentificationAlgorithm("HTTPS");
            ligacao.setSSLParameters(parametros);

            try {
                ligacao.connect(new InetSocketAddress(
                        "localhost", Caminhos.PORTA_AUTORIDADE), 5_000);
            } catch (java.net.ConnectException semServidor) {
                throw new IOException("Não foi possível contactar a "
                        + "Autoridade em localhost:" + Caminhos.PORTA_AUTORIDADE
                        + ". Está a correr?", semServidor);
            }
            ligacao.setSoTimeout(15_000);

            Protocolo.enviar(new DataOutputStream(ligacao.getOutputStream()),
                    Protocolo.CRIAR_CONTA, pedido.codificar());

            Protocolo.Mensagem resposta = Protocolo.receber(
                    new DataInputStream(ligacao.getInputStream()));

            if (resposta.tipo() == Protocolo.ERRO) {
                throw new IllegalStateException("Conta recusada: " + new String(
                        resposta.dados(), StandardCharsets.UTF_8));
            }
            if (resposta.tipo() != Protocolo.CERTIFICADO) {
                throw new IllegalStateException("Resposta inesperada.");
            }
            return resposta.dados();
        }
    }

    // ------------------------------------------------------------------
    // Contactos: só nomes, um por linha. O certificado é sempre pedido
    // ao relay e validado de novo quando é preciso.
    // ------------------------------------------------------------------

    public static List<String> contactos(String conta) {
        List<String> nomes = new ArrayList<>();
        try {
            for (String linha : Files.readAllLines(
                    Caminhos.contactos(conta), StandardCharsets.UTF_8)) {
                if (linha.matches("[a-z0-9_-]{1,32}")
                        && !nomes.contains(linha)) {
                    nomes.add(linha);
                }
            }
        } catch (IOException semFicheiro) {
            // Ainda não há contactos.
        }
        return nomes;
    }

    public static void adicionarContacto(String conta, String contacto)
            throws IOException {
        if (contactos(conta).contains(contacto)) {
            return;
        }
        Files.writeString(Caminhos.contactos(conta), contacto + "\n",
                StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
    }
}
