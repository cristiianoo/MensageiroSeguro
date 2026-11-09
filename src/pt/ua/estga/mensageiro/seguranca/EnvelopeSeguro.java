package pt.ua.estga.mensageiro.seguranca;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public final class EnvelopeSeguro {

    private static final SecureRandom ALEATORIO = new SecureRandom();
    private static final int VERSAO = 1;
    private static final int MAX_TEXTO = 16 * 1024;
    private static final int MAX_ENVELOPE = 60 * 1024;

    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT);

    private EnvelopeSeguro() {
    }

    public static byte[] criar(
            String remetente,
            String destinatario,
            byte[] texto,
            PrivateKey chaveRemetente,
            PublicKey chaveDestinatario) throws Exception {

        validarIdentidade(remetente);
        validarIdentidade(destinatario);

        if (texto.length > MAX_TEXTO) {
            throw new IllegalArgumentException("Mensagem demasiado grande.");
        }

        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(256, ALEATORIO);

        // Cada mensagem leva uma chave nova.
        SecretKey chaveAES = gerador.generateKey();
        byte[] nonce = new byte[12];
        ALEATORIO.nextBytes(nonce);

        ByteArrayOutputStream bytesCabecalho = new ByteArrayOutputStream();

        try (DataOutputStream cabecalho =
                new DataOutputStream(bytesCabecalho)) {
            cabecalho.writeInt(VERSAO);
            cabecalho.writeUTF(UUID.randomUUID().toString());
            cabecalho.writeUTF(remetente);
            cabecalho.writeUTF(destinatario);
        }

        byte[] metadados = bytesCabecalho.toByteArray();

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, chaveAES,
                new GCMParameterSpec(128, nonce));

        // Ligamos também os metadados à proteção GCM.
        aes.updateAAD(metadados);
        byte[] cifra = aes.doFinal(texto);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, chaveDestinatario, OAEP);
        byte[] chaveProtegida = rsa.doFinal(chaveAES.getEncoded());

        ByteArrayOutputStream bytesCorpo = new ByteArrayOutputStream();

        try (DataOutputStream corpo = new DataOutputStream(bytesCorpo)) {
            escreverCampo(corpo, metadados);
            escreverCampo(corpo, chaveProtegida);
            escreverCampo(corpo, nonce);
            escreverCampo(corpo, cifra);
        }

        byte[] corpo = bytesCorpo.toByteArray();

        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initSign(chaveRemetente, ALEATORIO);
        assinatura.update(corpo);
        byte[] assinaturaDigital = assinatura.sign();

        ByteArrayOutputStream bytesEnvelope = new ByteArrayOutputStream();

        try (DataOutputStream envelope =
                new DataOutputStream(bytesEnvelope)) {
            escreverCampo(envelope, corpo);
            escreverCampo(envelope, assinaturaDigital);
        }

        byte[] resultado = bytesEnvelope.toByteArray();

        if (resultado.length > MAX_ENVELOPE) {
            throw new IOException("Envelope demasiado grande.");
        }

        return resultado;
    }

    public static byte[] abrir(
            byte[] envelope,
            String remetenteEsperado,
            String destinatarioEsperado,
            PublicKey chaveRemetente,
            PrivateKey chaveDestinatario) throws Exception {

        if (envelope.length > MAX_ENVELOPE) {
            throw new IOException("Envelope demasiado grande.");
        }

        byte[] corpo;
        byte[] assinaturaDigital;

        try (DataInputStream entrada = new DataInputStream(
                new ByteArrayInputStream(envelope))) {
            corpo = lerCampo(entrada, MAX_ENVELOPE);
            assinaturaDigital = lerCampo(entrada, 1024);
            exigirFim(entrada);
        }

        Signature assinatura = Signature.getInstance("SHA256withRSA");
        assinatura.initVerify(chaveRemetente);
        assinatura.update(corpo);

        // Não tentamos decifrar um envelope com assinatura inválida.
        if (!assinatura.verify(assinaturaDigital)) {
            throw new GeneralSecurityException("Assinatura inválida.");
        }

        byte[] metadados;
        byte[] chaveProtegida;
        byte[] nonce;
        byte[] cifra;

        try (DataInputStream entrada = new DataInputStream(
                new ByteArrayInputStream(corpo))) {
            metadados = lerCampo(entrada, 1024);
            chaveProtegida = lerCampo(entrada, 1024);
            nonce = lerCampo(entrada, 12);
            cifra = lerCampo(entrada, MAX_TEXTO + 16);
            exigirFim(entrada);
        }

        if (nonce.length != 12) {
            throw new IOException("Nonce inválido.");
        }

        try (DataInputStream entrada = new DataInputStream(
                new ByteArrayInputStream(metadados))) {
            int versao = entrada.readInt();
            String identificador = entrada.readUTF();
            String remetente = entrada.readUTF();
            String destinatario = entrada.readUTF();
            exigirFim(entrada);

            validarIdentidade(remetente);
            validarIdentidade(destinatario);
            UUID.fromString(identificador);

            if (versao != VERSAO
                    || !remetenteEsperado.equals(remetente)
                    || !destinatarioEsperado.equals(destinatario)) {
                throw new GeneralSecurityException(
                        "Versão ou identidades do envelope inválidas.");
            }
        }

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, chaveDestinatario, OAEP);
        byte[] chaveAES = rsa.doFinal(chaveProtegida);

        try {
            if (chaveAES.length != 32) {
                throw new GeneralSecurityException("Chave AES inválida.");
            }

            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(chaveAES, "AES"),
                    new GCMParameterSpec(128, nonce));
            aes.updateAAD(metadados);

            return aes.doFinal(cifra);
        } finally {
            java.util.Arrays.fill(chaveAES, (byte) 0);
        }
    }

    private static void escreverCampo(
            DataOutputStream saida, byte[] dados) throws IOException {
        saida.writeInt(dados.length);
        saida.write(dados);
    }

    private static byte[] lerCampo(
            DataInputStream entrada, int limite) throws IOException {
        int tamanho = entrada.readInt();

        if (tamanho < 0 || tamanho > limite) {
            throw new IOException("Comprimento de campo inválido.");
        }

        byte[] dados = new byte[tamanho];
        entrada.readFully(dados);
        return dados;
    }

    private static void exigirFim(DataInputStream entrada)
            throws IOException {
        if (entrada.read() != -1) {
            throw new IOException("Dados adicionais inesperados.");
        }
    }

    private static void validarIdentidade(String identidade) {
        if (identidade == null
                || !identidade.matches("[a-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException("Identidade inválida.");
        }
    }
}
