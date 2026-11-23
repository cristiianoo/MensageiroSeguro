package pt.ua.estga.mensageiro.seguranca;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/**
 * Testa a validação dos certificados devolvidos pelo relay na descoberta.
 * Usa apenas os certificados públicos gerados pelo script de preparação.
 */
public final class TesteCertificados {

    public static void main(String[] args) throws Exception {
        byte[] joao = lerPem("certificados/publicos/joao.crt");
        byte[] relay = lerPem("certificados/publicos/relay.crt");
        byte[] ca = lerPem("certificados/publicos/ca-grupo09.crt");

        ValidacaoCertificado.validarUtilizador(joao, "joao");
        System.out.println("OK — certificado do joao aceite para joao.");

        // Um relay malicioso devolve um certificado válido de outra pessoa.
        rejeitar(joao, "cristiano",
                "certificado de outro utilizador rejeitado");

        // Certificado de servidor (EKU serverAuth) usado como utilizador.
        rejeitar(relay, "localhost",
                "certificado do relay rejeitado como utilizador");

        // O certificado da própria CA não serve de identidade.
        rejeitar(ca, "ca", "certificado da CA rejeitado como utilizador");

        // Bytes que não formam um certificado.
        byte[] lixo = joao.clone();
        lixo[lixo.length / 2] ^= 1;
        rejeitar(lixo, "joao", "certificado adulterado rejeitado");
    }

    private static void rejeitar(byte[] dados, String nome, String caso) {
        try {
            ValidacaoCertificado.validarUtilizador(dados, nome);
        } catch (Exception esperado) {
            System.out.println("OK — " + caso + ".");
            return;
        }
        throw new AssertionError("Aceite indevidamente: " + caso);
    }

    private static byte[] lerPem(String caminho) throws Exception {
        String pem = Files.readString(Path.of(caminho));
        return Base64.getMimeDecoder().decode(
                pem.replaceAll("-----[A-Z ]+-----", ""));
    }
}
