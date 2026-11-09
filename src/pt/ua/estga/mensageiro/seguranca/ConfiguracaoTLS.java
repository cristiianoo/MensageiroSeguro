package pt.ua.estga.mensageiro.seguranca;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class ConfiguracaoTLS {

    private ConfiguracaoTLS() {
    }

    public static SSLContext criarContexto(
            Path ficheiroIdentidade,
            char[] palavraPasseIdentidade,
            Path ficheiroConfianca,
            char[] palavraPasseConfianca)
            throws GeneralSecurityException, IOException {

        KeyStore identidade = carregar(
                ficheiroIdentidade,
                palavraPasseIdentidade);

        KeyManagerFactory gestoresChaves = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());

        gestoresChaves.init(identidade, palavraPasseIdentidade);

        KeyStore confianca = carregar(
                ficheiroConfianca,
                palavraPasseConfianca);

        TrustManagerFactory gestoresConfianca =
                TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());

        gestoresConfianca.init(confianca);

        SSLContext contexto = SSLContext.getInstance("TLSv1.3");

        contexto.init(
                gestoresChaves.getKeyManagers(),
                gestoresConfianca.getTrustManagers(),
                null);

        return contexto;
    }

    private static KeyStore carregar(Path ficheiro, char[] palavraPasse)
            throws GeneralSecurityException, IOException {

        KeyStore armazenamento = KeyStore.getInstance("PKCS12");

        try (InputStream entrada = Files.newInputStream(ficheiro)) {
            armazenamento.load(entrada, palavraPasse);
        }

        return armazenamento;
    }
}
