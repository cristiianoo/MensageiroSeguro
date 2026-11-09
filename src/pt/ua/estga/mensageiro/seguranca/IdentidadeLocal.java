package pt.ua.estga.mensageiro.seguranca;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public record IdentidadeLocal(
        PrivateKey chavePrivada,
        X509Certificate certificado) {

    public static IdentidadeLocal carregar(
            Path ficheiro,
            char[] palavraPasse,
            String alias) throws Exception {

        KeyStore armazenamento = KeyStore.getInstance("PKCS12");

        try (InputStream entrada = Files.newInputStream(ficheiro)) {
            armazenamento.load(entrada, palavraPasse);
        }

        if (!armazenamento.isKeyEntry(alias)) {
            throw new IllegalArgumentException(
                    "Identidade não encontrada: " + alias);
        }

        Key chave = armazenamento.getKey(alias, palavraPasse);

        if (!(chave instanceof PrivateKey chavePrivada)) {
            throw new IllegalArgumentException(
                    "A identidade não contém uma chave privada.");
        }

        if (!(armazenamento.getCertificate(alias)
                instanceof X509Certificate certificado)) {
            throw new IllegalArgumentException(
                    "A identidade não contém um certificado X.509.");
        }

        certificado.checkValidity();

        // O envelope que escolhemos usa chaves RSA.
        if (!"RSA".equals(chavePrivada.getAlgorithm())
                || !"RSA".equals(
                        certificado.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException(
                    "Esta versão exige uma identidade RSA.");
        }

        return new IdentidadeLocal(chavePrivada, certificado);
    }
}
