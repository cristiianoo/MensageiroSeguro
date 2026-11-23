package pt.ua.estga.mensageiro.seguranca;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Emissão de certificados X.509 v3 só com a API pública do JDK.
 *
 * O JDK lê e valida certificados, mas não tem API pública para os criar
 * (o keytool usa classes internas). Aqui escrevemos a estrutura em DER
 * (RFC 5280) e assinamos com Signature("SHA256withRSA"). O resultado é
 * relido por CertificateFactory e verificado com a chave do emissor.
 */
public final class CertificadoX509 {

    /** Para que serve o certificado emitido. */
    public enum Tipo {
        /** Utilizador: autentica-se no relay e assina envelopes. */
        CLIENTE,
        /** Relay ou Autoridade: servidor TLS em localhost. */
        SERVIDOR
    }

    // Identificadores de objeto (OID) usados.
    private static final String SHA256_COM_RSA = "1.2.840.113549.1.1.11";
    private static final String CN = "2.5.4.3";
    private static final String OU = "2.5.4.11";
    private static final String O = "2.5.4.10";
    private static final String BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String KEY_USAGE = "2.5.29.15";
    private static final String EXT_KEY_USAGE = "2.5.29.37";
    private static final String SUBJECT_ALT_NAME = "2.5.29.17";
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    private static final SecureRandom ALEATORIO = new SecureRandom();

    private CertificadoX509() {
    }

    /** Certificado autoassinado da CA (BasicConstraints CA:true). */
    public static X509Certificate criarCA(
            KeyPair chaves, String cn, Duration validade) throws Exception {

        byte[] nome = nome(cn, "Seguranca Informatica", "ESTGA");

        byte[] extensoes = sequencia(
                extensao(BASIC_CONSTRAINTS, true,
                        sequencia(tlv(0x01, new byte[] {(byte) 0xFF}))),
                // keyCertSign (bit 5) e cRLSign (bit 6).
                extensao(KEY_USAGE, true, bits(5, 6)));

        return assinar(nome, nome, chaves.getPublic(), validade,
                extensoes, chaves.getPrivate(), chaves.getPublic());
    }

    /** Certificado de utilizador ou de servidor, assinado pela CA. */
    public static X509Certificate emitir(
            X509Certificate ca,
            PrivateKey chaveCA,
            PublicKey chaveSujeito,
            String cn,
            Tipo tipo,
            Duration validade) throws Exception {

        byte[] sujeito = nome(cn,
                tipo == Tipo.CLIENTE ? "Clientes" : "Servidores", "ESTGA");

        byte[] extensoes;

        if (tipo == Tipo.CLIENTE) {
            extensoes = sequencia(
                    extensao(BASIC_CONSTRAINTS, true, sequencia()),
                    // digitalSignature (0) e keyEncipherment (2):
                    // assina envelopes e recebe a chave AES por RSA-OAEP.
                    extensao(KEY_USAGE, true, bits(0, 2)),
                    extensao(EXT_KEY_USAGE, false,
                            sequencia(oid(CLIENT_AUTH))));
        } else {
            extensoes = sequencia(
                    extensao(BASIC_CONSTRAINTS, true, sequencia()),
                    extensao(KEY_USAGE, true, bits(0)),
                    extensao(EXT_KEY_USAGE, false,
                            sequencia(oid(SERVER_AUTH))),
                    // dNSName [2] "localhost" e iPAddress [7] 127.0.0.1.
                    extensao(SUBJECT_ALT_NAME, false, sequencia(
                            tlv(0x82, "localhost".getBytes(
                                    StandardCharsets.US_ASCII)),
                            tlv(0x87, new byte[] {127, 0, 0, 1}))));
        }

        // O emissor é copiado byte a byte do sujeito da CA, para que a
        // validação PKIX encontre a correspondência exata.
        return assinar(ca.getSubjectX500Principal().getEncoded(), sujeito,
                chaveSujeito, validade, extensoes, chaveCA, ca.getPublicKey());
    }

    /** Converte para o formato PEM (texto Base64 entre marcadores). */
    public static String pem(X509Certificate certificado) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(certificado.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    // ------------------------------------------------------------------
    // Estrutura do certificado
    // ------------------------------------------------------------------

    private static X509Certificate assinar(
            byte[] emissor,
            byte[] sujeito,
            PublicKey chaveSujeito,
            Duration validade,
            byte[] extensoes,
            PrivateKey chaveEmissor,
            PublicKey chavePublicaEmissor) throws Exception {

        // Número de série aleatório e positivo (até 20 bytes, RFC 5280).
        BigInteger serie = new BigInteger(127, ALEATORIO).add(BigInteger.ONE);

        // Uma pequena margem para relógios ligeiramente desacertados.
        Instant inicio = Instant.now().minus(Duration.ofMinutes(5));

        byte[] algoritmo = sequencia(oid(SHA256_COM_RSA), tlv(0x05));

        byte[] tbs = sequencia(
                tlv(0xA0, inteiro(BigInteger.TWO)),           // versão v3
                inteiro(serie),
                algoritmo,
                emissor,
                sequencia(tempo(inicio), tempo(inicio.plus(validade))),
                sujeito,
                chaveSujeito.getEncoded(),                    // SPKI em DER
                tlv(0xA3, extensoes));

        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initSign(chaveEmissor);
        assinatura.update(tbs);

        byte[] der = sequencia(tbs, algoritmo,
                bitString(assinatura.sign()));

        X509Certificate certificado = (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(der));

        // Confirmamos que o que escrevemos é o que o JDK lê.
        certificado.verify(chavePublicaEmissor);
        return certificado;
    }

    private static byte[] nome(String cn, String ou, String o) {
        // Do mais geral para o mais específico: O, OU, CN.
        return sequencia(atributo(O, o), atributo(OU, ou), atributo(CN, cn));
    }

    private static byte[] atributo(String tipo, String valor) {
        return tlv(0x31, sequencia(oid(tipo),
                tlv(0x0C, valor.getBytes(StandardCharsets.UTF_8))));
    }

    private static byte[] extensao(String id, boolean critica, byte[] valor) {
        return critica
                ? sequencia(oid(id), tlv(0x01, new byte[] {(byte) 0xFF}),
                        tlv(0x04, valor))
                : sequencia(oid(id), tlv(0x04, valor));
    }

    /** KeyUsage: BIT STRING com os bits indicados (0 = mais à esquerda). */
    private static byte[] bits(int... posicoes) {
        int valor = 0;
        int ultimo = 0;
        for (int posicao : posicoes) {
            valor |= 0x80 >>> posicao;
            ultimo = Math.max(ultimo, posicao);
        }
        // DER: os bits a zero no fim não são codificados.
        return tlv(0x03, new byte[] {(byte) (7 - ultimo), (byte) valor});
    }

    private static byte[] tempo(Instant instante) {
        // UTCTime serve até 2049, como manda a RFC 5280.
        String texto = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")
                .withZone(ZoneOffset.UTC).format(instante);
        return tlv(0x17, texto.getBytes(StandardCharsets.US_ASCII));
    }

    // ------------------------------------------------------------------
    // Codificação DER: etiqueta, comprimento, valor
    // ------------------------------------------------------------------

    private static byte[] sequencia(byte[]... partes) {
        ByteArrayOutputStream conteudo = new ByteArrayOutputStream();
        for (byte[] parte : partes) {
            conteudo.writeBytes(parte);
        }
        return tlv(0x30, conteudo.toByteArray());
    }

    private static byte[] inteiro(BigInteger valor) {
        // toByteArray já devolve o complemento para dois mínimo.
        return tlv(0x02, valor.toByteArray());
    }

    private static byte[] bitString(byte[] dados) {
        byte[] valor = new byte[dados.length + 1];   // 0 bits por usar
        System.arraycopy(dados, 0, valor, 1, dados.length);
        return tlv(0x03, valor);
    }

    private static byte[] oid(String texto) {
        String[] arcos = texto.split("\\.");
        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        saida.write(40 * Integer.parseInt(arcos[0])
                + Integer.parseInt(arcos[1]));

        for (int i = 2; i < arcos.length; i++) {
            long arco = Long.parseLong(arcos[i]);
            // Base 128, com o bit mais alto a 1 em todos menos no último.
            int grupos = 1;
            for (long resto = arco >>> 7; resto != 0; resto >>>= 7) {
                grupos++;
            }
            for (int g = grupos - 1; g >= 0; g--) {
                int bits7 = (int) ((arco >>> (7 * g)) & 0x7F);
                saida.write(g == 0 ? bits7 : bits7 | 0x80);
            }
        }
        return tlv(0x06, saida.toByteArray());
    }

    private static byte[] tlv(int etiqueta, byte... valor) {
        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        saida.write(etiqueta);

        int n = valor.length;
        if (n < 0x80) {
            saida.write(n);                       // forma curta
        } else {
            int bytes = (32 - Integer.numberOfLeadingZeros(n) + 7) / 8;
            saida.write(0x80 | bytes);            // forma longa
            for (int i = bytes - 1; i >= 0; i--) {
                saida.write(n >>> (8 * i));
            }
        }

        saida.writeBytes(valor);
        return saida.toByteArray();
    }
}
