package pt.ua.estga.mensageiro.auditoria;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Verificador independente do registo de auditoria do relay.
 *
 * Não depende de nenhuma classe do relay: só do formato documentado,
 * do certificado público do relay e do certificado da CA.
 *
 * Utilização:
 *   VerificadorAuditoria <auditoria.log> <relay.crt> <ca.crt>
 *
 * Código de saída 0 se o registo for íntegro, 1 caso contrário.
 */
public final class VerificadorAuditoria {

    private static final HexFormat HEX = HexFormat.of();

    private VerificadorAuditoria() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Utilização: VerificadorAuditoria "
                    + "<auditoria.log> <relay.crt> <ca.crt>");
            System.exit(2);
        }

        PublicKey chaveRelay = validarCertificadoRelay(
                Path.of(args[1]), Path.of(args[2]));

        List<String> linhas = Files.readAllLines(
                Path.of(args[0]), StandardCharsets.UTF_8);

        long seqEsperado = 1;
        byte[] hashAnterior = new byte[32];
        long ultimoPontoValido = 0;
        int pontos = 0;

        for (int i = 0; i < linhas.size(); i++) {
            int numeroLinha = i + 1;
            String linha = linhas.get(i);
            String[] p = linha.split("\\|", -1);

            try {
                if (p[0].equals("E") && p.length == 6) {
                    String linhaSemHash = linha.substring(
                            0, linha.lastIndexOf('|'));

                    hashAnterior = verificarEntrada(
                            p, linhaSemHash, seqEsperado, hashAnterior);
                    seqEsperado++;

                } else if (p[0].equals("C") && p.length == 4) {
                    verificarPonto(p, seqEsperado - 1, hashAnterior,
                            chaveRelay);
                    ultimoPontoValido = seqEsperado - 1;
                    pontos++;

                } else {
                    throw new IllegalStateException("linha mal formada");
                }
            } catch (Exception erro) {
                System.out.println("REGISTO INVÁLIDO na linha "
                        + numeroLinha + ": " + erro.getMessage());
                System.out.println("  > " + linha);
                System.exit(1);
            }
        }

        long total = seqEsperado - 1;

        System.out.println("Cadeia íntegra: " + total + " entradas, "
                + pontos + (pontos == 1
                        ? " ponto de controlo assinado válido."
                        : " pontos de controlo assinados válidos."));

        if (ultimoPontoValido < total) {
            // Estas entradas podem ser truncadas sem deteção.
            System.out.println("AVISO: as entradas " + (ultimoPontoValido + 1)
                    + " a " + total + " ainda não estão cobertas por "
                    + "um ponto de controlo assinado.");
        }

        System.out.println("Último ponto assinado: seq="
                + ultimoPontoValido
                + " (guarde este valor fora do relay para detetar "
                + "truncagens futuras).");
    }

    /**
     * Verifica uma entrada "E|seq|instante|tipo|campos|hash".
     *
     * @param p             campos da linha, já separados por '|'
     * @param linhaSemHash  a linha sem o último campo (o que foi "hashado")
     * @param seqEsperado   número de sequência que esta entrada deve ter
     * @param hashAnterior  hash da entrada anterior (32 zeros na primeira)
     * @return o hash desta entrada, que passa a ser o "anterior"
     * @throws IllegalStateException com uma descrição do problema
     */
    private static byte[] verificarEntrada(
            String[] p,
            String linhaSemHash,
            long seqEsperado,
            byte[] hashAnterior) throws Exception {

        // Sequência: deteta entradas removidas ou reordenadas.
        long seq = Long.parseLong(p[1]);

        if (seq != seqEsperado) {
            throw new IllegalStateException("esperada a entrada "
                    + seqEsperado + ", encontrada a " + seq
                    + " (entrada removida ou reordenada)");
        }

        // Cadeia: deteta entradas alteradas (ou cujo antecessor mudou).
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(hashAnterior);
        sha.update(linhaSemHash.getBytes(StandardCharsets.UTF_8));
        byte[] calculado = sha.digest();

        if (!MessageDigest.isEqual(calculado, HEX.parseHex(p[5]))) {
            throw new IllegalStateException(
                    "hash não corresponde (entrada alterada)");
        }

        return calculado;
    }

    /** Verifica um ponto de controlo "C|seq|hash|assinatura". */
    private static void verificarPonto(
            String[] p,
            long seqAtual,
            byte[] hashAtual,
            PublicKey chaveRelay) throws Exception {

        if (Long.parseLong(p[1]) != seqAtual
                || !MessageDigest.isEqual(HEX.parseHex(p[2]), hashAtual)) {
            throw new IllegalStateException(
                    "ponto de controlo não corresponde à cadeia");
        }

        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initVerify(chaveRelay);
        assinatura.update(("C|" + p[1] + "|" + p[2])
                .getBytes(StandardCharsets.UTF_8));

        if (!assinatura.verify(Base64.getDecoder().decode(p[3]))) {
            throw new IllegalStateException(
                    "assinatura do ponto de controlo inválida");
        }
    }

    /** Só confiamos na chave do relay se a CA do grupo a tiver emitido. */
    private static PublicKey validarCertificadoRelay(
            Path ficheiroRelay, Path ficheiroCA) throws Exception {

        CertificateFactory fabrica = CertificateFactory.getInstance("X.509");
        X509Certificate relay;
        X509Certificate ca;

        try (InputStream entrada = Files.newInputStream(ficheiroRelay)) {
            relay = (X509Certificate) fabrica.generateCertificate(entrada);
        }

        try (InputStream entrada = Files.newInputStream(ficheiroCA)) {
            ca = (X509Certificate) fabrica.generateCertificate(entrada);
        }

        PKIXParameters parametros =
                new PKIXParameters(Set.of(new TrustAnchor(ca, null)));
        parametros.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(
                fabrica.generateCertPath(List.of(relay)), parametros);

        return relay.getPublicKey();
    }
}
