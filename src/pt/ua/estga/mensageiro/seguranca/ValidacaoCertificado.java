package pt.ua.estga.mensageiro.seguranca;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public final class ValidacaoCertificado {

    private ValidacaoCertificado() {
    }

    public static X509Certificate validarUtilizador(
            byte[] dados, String identidadeEsperada) throws Exception {

        CertificateFactory fabrica =
                CertificateFactory.getInstance("X.509");

        X509Certificate certificado;

        try (ByteArrayInputStream entrada =
                new ByteArrayInputStream(dados)) {
            certificado = (X509Certificate)
                    fabrica.generateCertificate(entrada);

            if (entrada.available() != 0) {
                throw new IllegalArgumentException(
                        "Dados adicionais depois do certificado.");
            }
        }

        X509Certificate ca;

        // A CA é configurada localmente, não vem do relay.
        try (InputStream entrada = Files.newInputStream(
                Path.of("certificados/publicos/ca-grupo09.crt"))) {
            ca = (X509Certificate) fabrica.generateCertificate(entrada);
        }

        ca.checkValidity();

        CertPath cadeia = fabrica.generateCertPath(List.of(certificado));

        PKIXParameters parametros = new PKIXParameters(
                Set.of(new TrustAnchor(ca, null)));

        // Ainda não temos um mecanismo de revogação.
        parametros.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(cadeia, parametros);

        if (certificado.getBasicConstraints() != -1) {
            throw new IllegalArgumentException(
                    "Era esperado um certificado de utilizador.");
        }

        List<String> utilizacoes = certificado.getExtendedKeyUsage();

        if (utilizacoes == null
                || !utilizacoes.contains("1.3.6.1.5.5.7.3.2")) {
            throw new IllegalArgumentException(
                    "Certificado sem utilização clientAuth.");
        }

        boolean[] permissoes = certificado.getKeyUsage();

        if (permissoes == null || !permissoes[0]) {
            throw new IllegalArgumentException(
                    "Certificado sem permissão para assinatura.");
        }

        String identidade = obterIdentidade(certificado);

        // Um certificado válido de outra pessoa não serve.
        if (!identidadeEsperada.equals(identidade)) {
            throw new IllegalArgumentException(
                    "O certificado não pertence ao utilizador procurado.");
        }

        return certificado;
    }

    private static String obterIdentidade(X509Certificate certificado)
            throws Exception {

        LdapName nome = new LdapName(
                certificado.getSubjectX500Principal().getName());

        String identidade = null;

        for (Rdn atributo : nome.getRdns()) {
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

        if (identidade == null
                || !identidade.matches("[a-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException(
                    "Identidade inválida no certificado.");
        }

        return identidade;
    }
}
