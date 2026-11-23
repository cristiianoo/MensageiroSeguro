package pt.ua.estga.mensageiro.seguranca;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;

/**
 * Testa a validação dos certificados devolvidos pelo relay na descoberta.
 * Cria uma CA de teste em memória: não depende de nenhum ficheiro.
 */
public final class TesteCertificados {

    private static final Duration ANO = Duration.ofDays(365);

    public static void main(String[] args) throws Exception {
        KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
        gerador.initialize(3072);

        KeyPair chavesCA = gerador.generateKeyPair();
        X509Certificate ca = CertificadoX509.criarCA(chavesCA, "CA Teste", ANO);

        X509Certificate joao = CertificadoX509.emitir(ca, chavesCA.getPrivate(),
                gerador.generateKeyPair().getPublic(), "joao",
                CertificadoX509.Tipo.CLIENTE, ANO);
        X509Certificate relay = CertificadoX509.emitir(ca, chavesCA.getPrivate(),
                gerador.generateKeyPair().getPublic(), "localhost",
                CertificadoX509.Tipo.SERVIDOR, ANO);

        // Outra CA, com o mesmo nome: um atacante que cria a sua própria CA.
        KeyPair chavesFalsa = gerador.generateKeyPair();
        X509Certificate caFalsa =
                CertificadoX509.criarCA(chavesFalsa, "CA Teste", ANO);
        X509Certificate joaoFalso = CertificadoX509.emitir(caFalsa,
                chavesFalsa.getPrivate(), gerador.generateKeyPair().getPublic(),
                "joao", CertificadoX509.Tipo.CLIENTE, ANO);

        ValidacaoCertificado.validarUtilizador(joao.getEncoded(), "joao", ca);
        System.out.println("OK — certificado do joao aceite para joao.");

        // Um relay malicioso devolve um certificado válido de outra pessoa.
        rejeitar(joao.getEncoded(), "cristiano", ca,
                "certificado de outro utilizador rejeitado");

        // Certificado de servidor (EKU serverAuth) usado como utilizador.
        rejeitar(relay.getEncoded(), "localhost", ca,
                "certificado do relay rejeitado como utilizador");

        // O certificado da própria CA não serve de identidade.
        rejeitar(ca.getEncoded(), "ca", ca,
                "certificado da CA rejeitado como utilizador");

        // Mesmo nome, mesma estrutura, mas emitido por outra CA.
        rejeitar(joaoFalso.getEncoded(), "joao", ca,
                "certificado de outra CA rejeitado");

        // Bytes alterados.
        byte[] lixo = joao.getEncoded();
        lixo[lixo.length / 2] ^= 1;
        rejeitar(lixo, "joao", ca, "certificado adulterado rejeitado");
    }

    private static void rejeitar(byte[] dados, String nome,
            X509Certificate ca, String caso) {
        try {
            ValidacaoCertificado.validarUtilizador(dados, nome, ca);
        } catch (Exception esperado) {
            System.out.println("OK — " + caso + ".");
            return;
        }
        throw new AssertionError("Aceite indevidamente: " + caso);
    }
}
