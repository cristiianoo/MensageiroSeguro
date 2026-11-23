package pt.ua.estga.mensageiro.seguranca;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

public final class TesteEnvelope {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
        gerador.initialize(3072);

        // São chaves temporárias, só para este teste.
        KeyPair joao = gerador.generateKeyPair();
        KeyPair cristiano = gerador.generateKeyPair();
        KeyPair terceiro = gerador.generateKeyPair();

        byte[] original = "Olá, Cristiano! Primeira mensagem protegida."
                .getBytes(StandardCharsets.UTF_8);

        byte[] envelope = EnvelopeSeguro.criar(
                "joao",
                "cristiano",
                original,
                joao.getPrivate(),
                cristiano.getPublic());

        byte[] recuperado = EnvelopeSeguro.abrir(
                envelope,
                "joao",
                "cristiano",
                joao.getPublic(),
                cristiano.getPrivate());

        if (!Arrays.equals(original, recuperado)) {
            throw new AssertionError(
                    "O conteúdo recuperado não corresponde ao original.");
        }

        System.out.println("OK — conteúdo recuperado corretamente.");
        System.out.println(new String(recuperado, StandardCharsets.UTF_8));

        byte[] adulterado = envelope.clone();

        // Alteramos um byte da assinatura, sem mudar o formato.
        adulterado[adulterado.length - 1] ^= 1;

        try {
            EnvelopeSeguro.abrir(
                    adulterado,
                    "joao",
                    "cristiano",
                    joao.getPublic(),
                    cristiano.getPrivate());

            throw new AssertionError("O envelope adulterado foi aceite.");
        } catch (GeneralSecurityException esperado) {
            System.out.println("OK — envelope adulterado rejeitado.");
        }


                byte[] cifraAlterada = envelope.clone();

        // Localizamos o conteúdo cifrado dentro do envelope.
        java.nio.ByteBuffer estrutura =
                java.nio.ByteBuffer.wrap(cifraAlterada);

        estrutura.getInt(); // Comprimento do corpo.

        int tamanhoMetadados = estrutura.getInt();
        estrutura.position(estrutura.position() + tamanhoMetadados);

        int tamanhoChave = estrutura.getInt();
        estrutura.position(estrutura.position() + tamanhoChave);

        int tamanhoNonce = estrutura.getInt();
        estrutura.position(estrutura.position() + tamanhoNonce);

        int tamanhoCifra = estrutura.getInt();

        if (tamanhoCifra < 1) {
            throw new AssertionError("O teste esperava conteúdo cifrado.");
        }

        cifraAlterada[estrutura.position()] ^= 1;

        try {
            EnvelopeSeguro.abrir(
                    cifraAlterada,
                    "joao",
                    "cristiano",
                    joao.getPublic(),
                    cristiano.getPrivate());

            throw new AssertionError("A cifra alterada foi aceite.");
        } catch (GeneralSecurityException esperado) {
            System.out.println("OK — conteúdo cifrado alterado rejeitado.");
        }

        byte[] metadadosAlterados = envelope.clone();

        java.nio.ByteBuffer cabecalho =
                java.nio.ByteBuffer.wrap(metadadosAlterados);

        cabecalho.getInt(); // Comprimento do corpo.
        cabecalho.getInt(); // Comprimento dos metadados.
        cabecalho.getInt(); // Versão.

        int tamanhoIdentificador =
                Short.toUnsignedInt(cabecalho.getShort());

        if (tamanhoIdentificador < 1) {
            throw new AssertionError("O teste esperava um identificador.");
        }

        int posicaoIdentificador = cabecalho.position();

        // Mudamos um carácter do UUID, mantendo o formato válido.
        metadadosAlterados[posicaoIdentificador] =
                metadadosAlterados[posicaoIdentificador] == 'a'
                        ? (byte) 'b' : (byte) 'a';

        try {
            EnvelopeSeguro.abrir(
                    metadadosAlterados,
                    "joao",
                    "cristiano",
                    joao.getPublic(),
                    cristiano.getPrivate());

            throw new AssertionError("Os metadados alterados foram aceites.");
        } catch (GeneralSecurityException esperado) {
            System.out.println("OK — metadados alterados rejeitados.");
        }


        try {
            EnvelopeSeguro.abrir(
                    envelope,
                    "joao",
                    "cristiano",
                    joao.getPublic(),
                    terceiro.getPrivate());

            throw new AssertionError(
                    "Uma chave privada diferente recuperou o conteúdo.");
        } catch (GeneralSecurityException esperado) {
            System.out.println("OK — chave privada diferente rejeitada.");
        }

        // Ataque de ordem: um terceiro remove a assinatura do João e
        // assina o mesmo corpo com a sua chave, para parecer o autor.
        // O relay indicaria "mallory" como remetente da sessão TLS.
        byte[] reassinado = reassinar(envelope, terceiro);

        try {
            EnvelopeSeguro.abrir(
                    reassinado,
                    "mallory",
                    "cristiano",
                    terceiro.getPublic(),
                    cristiano.getPrivate());

            throw new AssertionError("O envelope reassinado foi aceite.");
        } catch (GeneralSecurityException esperado) {
            System.out.println(
                    "OK — corpo reassinado por terceiro rejeitado.");
        }

        // Ataque de ordem: o envelope do João para o Cristiano é
        // reencaminhado a outra pessoa como se lhe fosse dirigido.
        try {
            EnvelopeSeguro.abrir(
                    envelope,
                    "joao",
                    "ana",
                    joao.getPublic(),
                    terceiro.getPrivate());

            throw new AssertionError("O envelope reencaminhado foi aceite.");
        } catch (GeneralSecurityException esperado) {
            System.out.println(
                    "OK — envelope reencaminhado a outro destinatário rejeitado.");
        }
    }

    /** Substitui a assinatura do envelope pela de outra chave. */
    private static byte[] reassinar(byte[] envelope, KeyPair atacante)
            throws Exception {

        java.nio.ByteBuffer entrada = java.nio.ByteBuffer.wrap(envelope);
        byte[] corpo = new byte[entrada.getInt()];
        entrada.get(corpo);

        java.security.Signature assinatura =
                java.security.Signature.getInstance("SHA256withRSA");
        assinatura.initSign(atacante.getPrivate());
        assinatura.update(corpo);
        byte[] novaAssinatura = assinatura.sign();

        java.io.ByteArrayOutputStream bytes =
                new java.io.ByteArrayOutputStream();

        try (java.io.DataOutputStream saida =
                new java.io.DataOutputStream(bytes)) {
            saida.writeInt(corpo.length);
            saida.write(corpo);
            saida.writeInt(novaAssinatura.length);
            saida.write(novaAssinatura);
        }

        return bytes.toByteArray();
    }
}
