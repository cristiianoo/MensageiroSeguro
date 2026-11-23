package pt.ua.estga.mensageiro.seguranca;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public final class ConfiguracaoTLS {

    /** A palavra-passe não abre o ficheiro PKCS12 indicado. */
    public static final class PalavraPasseIncorreta extends IOException {
        PalavraPasseIncorreta(Path ficheiro, IOException causa) {
            super("Palavra-passe incorreta para " + ficheiro + ".", causa);
        }
    }

    private ConfiguracaoTLS() {
    }

    /**
     * Contexto com identidade própria (TLS mútuo): relay, Autoridade
     * e clientes já com conta. A confiança é só a CA do grupo.
     */
    public static SSLContext criarContexto(
            Path ficheiroIdentidade,
            char[] palavraPasseIdentidade)
            throws GeneralSecurityException, IOException {

        KeyStore identidade = carregar(
                ficheiroIdentidade,
                palavraPasseIdentidade);

        KeyManagerFactory gestoresChaves = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());

        gestoresChaves.init(identidade, palavraPasseIdentidade);

        SSLContext contexto = SSLContext.getInstance("TLSv1.3");
        contexto.init(gestoresChaves.getKeyManagers(), confianca(), null);
        return contexto;
    }

    /**
     * Contexto sem identidade própria: só para quem ainda não tem conta
     * e vai pedir o primeiro certificado à Autoridade.
     */
    public static SSLContext criarContextoSemIdentidade()
            throws GeneralSecurityException, IOException {

        SSLContext contexto = SSLContext.getInstance("TLSv1.3");
        contexto.init(null, confianca(), null);
        return contexto;
    }

    /**
     * O certificado da CA é público: não precisa de palavra-passe.
     * Precisa, sim, de vir de uma fonte fiável (instalado com o
     * programa), nunca do relay.
     */
    public static X509Certificate lerCA() throws GeneralSecurityException, IOException {
        try (InputStream entrada = Files.newInputStream(Caminhos.CA_PUBLICO)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(entrada);
        }
    }

    private static TrustManager[] confianca()
            throws GeneralSecurityException, IOException {

        KeyStore ancoras = KeyStore.getInstance("PKCS12");
        ancoras.load(null, null);
        ancoras.setCertificateEntry("ca-grupo09", lerCA());

        TrustManagerFactory gestores = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        gestores.init(ancoras);
        return gestores.getTrustManagers();
    }

    private static KeyStore carregar(Path ficheiro, char[] palavraPasse)
            throws GeneralSecurityException, IOException {

        KeyStore armazenamento = KeyStore.getInstance("PKCS12");

        try (InputStream entrada = Files.newInputStream(ficheiro)) {
            armazenamento.load(entrada, palavraPasse);
        } catch (IOException erro) {
            // O PKCS12 está cifrado com a palavra-passe: se ela estiver
            // errada, a decifra falha e a causa é UnrecoverableKeyException.
            if (erro.getCause() instanceof UnrecoverableKeyException) {
                throw new PalavraPasseIncorreta(ficheiro, erro);
            }
            throw erro;
        }

        return armazenamento;
    }
}
