package pt.ua.estga.mensageiro.relay;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Registo de auditoria com hash encadeado e pontos de controlo assinados.
 *
 * Formato (uma linha por registo, texto UTF-8):
 *
 *   E|seq|instante|tipo|campos|hash
 *       hash = SHA-256(hashAnterior || "E|seq|instante|tipo|campos")
 *       O primeiro hashAnterior são 32 bytes a zero.
 *
 *   C|seq|hash|assinatura
 *       Ponto de controlo: assinatura SHA256withRSA do relay sobre
 *       "C|seq|hash", em que seq/hash são os da última entrada.
 *
 * Os campos nunca contêm o conteúdo das mensagens (minimização).
 */
public final class RegistoAuditoria implements AutoCloseable {

    public static final String SEPARADOR = "|";

    // Assinamos um ponto de controlo a cada N entradas novas.
    private static final int ENTRADAS_POR_PONTO = 10;

    private static final HexFormat HEX = HexFormat.of();

    private final PrivateKey chaveRelay;
    private final BufferedWriter saida;

    private long seq;
    private byte[] ultimoHash;
    private long seqUltimoPonto;

    public RegistoAuditoria(Path ficheiro, PrivateKey chaveRelay)
            throws IOException {

        this.chaveRelay = chaveRelay;
        Files.createDirectories(ficheiro.toAbsolutePath().getParent());

        // Continuamos a cadeia de um registo já existente.
        seq = 0;
        ultimoHash = new byte[32];
        seqUltimoPonto = 0;

        if (Files.exists(ficheiro)) {
            List<String> linhas =
                    Files.readAllLines(ficheiro, StandardCharsets.UTF_8);

            for (String linha : linhas) {
                String[] p = linha.split("\\|", -1);

                if (p[0].equals("E") && p.length == 6) {
                    seq = Long.parseLong(p[1]);
                    ultimoHash = HEX.parseHex(p[5]);
                } else if (p[0].equals("C") && p.length == 4) {
                    seqUltimoPonto = Long.parseLong(p[1]);
                }
            }
        }

        saida = Files.newBufferedWriter(ficheiro, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    /**
     * Acrescenta um evento.
     *
     * @param tipo   REGISTO, ENVIO, LEVANTAMENTO, FALHA, ...
     * @param campos valores sem '|' nem ',' (identidades, códigos)
     */
    public synchronized void registar(String tipo, String... campos) {
        try {
            for (String campo : campos) {
                if (campo.contains(SEPARADOR) || campo.contains(",")) {
                    throw new IllegalArgumentException(
                            "Campo de auditoria inválido.");
                }
            }

            seq++;

            String linhaSemHash = String.join(SEPARADOR,
                    "E",
                    Long.toString(seq),
                    // Precisão ao segundo chega para auditoria.
                    Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
                    tipo,
                    String.join(",", campos));

            ultimoHash = encadear(ultimoHash, linhaSemHash);

            saida.write(linhaSemHash + SEPARADOR + HEX.formatHex(ultimoHash));
            saida.newLine();
            saida.flush();

            if (seq - seqUltimoPonto >= ENTRADAS_POR_PONTO) {
                pontoDeControlo();
            }
        } catch (Exception erro) {
            // A auditoria não pode falhar em silêncio.
            System.err.println("Falha no registo de auditoria: "
                    + erro.getMessage());
        }
    }

    /** Assina o estado atual da cadeia, se houver entradas novas. */
    public synchronized void pontoDeControlo() throws Exception {
        if (seq == seqUltimoPonto) {
            return;
        }

        String dados = String.join(SEPARADOR,
                "C", Long.toString(seq), HEX.formatHex(ultimoHash));

        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initSign(chaveRelay);
        assinatura.update(dados.getBytes(StandardCharsets.UTF_8));

        saida.write(dados + SEPARADOR
                + Base64.getEncoder().encodeToString(assinatura.sign()));
        saida.newLine();
        saida.flush();

        seqUltimoPonto = seq;
    }

    /** Função de encadeamento, igual à usada pelo verificador. */
    static byte[] encadear(byte[] hashAnterior, String linhaSemHash)
            throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(hashAnterior);
        sha.update(linhaSemHash.getBytes(StandardCharsets.UTF_8));
        return sha.digest();
    }

    @Override
    public synchronized void close() throws IOException {
        try {
            pontoDeControlo();
        } catch (Exception erro) {
            System.err.println("Último ponto de controlo falhou: "
                    + erro.getMessage());
        }
        saida.close();
    }
}
