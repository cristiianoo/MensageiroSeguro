package pt.ua.estga.mensageiro.autoridade;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Set;

/**
 * Pedido de criação de conta: nome, chave pública e prova de posse.
 *
 * A prova de posse é uma assinatura, com a chave privada do próprio
 * pedido, sobre o nome e a chave pública. Sem ela, alguém podia registar
 * a chave pública de outra pessoa com o seu nome.
 *
 * Usado pelo cliente (criar) e pela Autoridade (ler e validar).
 */
public record PedidoConta(String nome, byte[] chavePublica, byte[] assinatura) {

    /** Separa estas assinaturas de qualquer outra feita com a mesma chave. */
    private static final String CONTEXTO = "MensageiroSeguro/criar-conta/v1";

    private static final Set<String> RESERVADOS =
            Set.of("relay", "localhost", "autoridade", "ca", "admin", "root");

    public PedidoConta {
        chavePublica = chavePublica.clone();
        assinatura = assinatura.clone();
    }

    @Override
    public byte[] chavePublica() {
        return chavePublica.clone();
    }

    @Override
    public byte[] assinatura() {
        return assinatura.clone();
    }

    /** Lado do cliente: assina o pedido com a chave que acabou de gerar. */
    public static PedidoConta criar(String nome, KeyPair chaves)
            throws Exception {

        validarNome(nome);
        byte[] publica = chaves.getPublic().getEncoded();

        Signature assinador = Signature.getInstance("SHA256withRSA");
        assinador.initSign(chaves.getPrivate());
        assinador.update(dadosAssinados(nome, publica));

        return new PedidoConta(nome, publica, assinador.sign());
    }

    /**
     * Lado da Autoridade: confirma o formato, o tamanho da chave e a prova
     * de posse. Devolve a chave pública que vai ser certificada.
     */
    public PublicKey validar() throws Exception {
        validarNome(nome);

        PublicKey chave = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(chavePublica));

        // Só aceitamos a codificação canónica (sem bytes extra).
        if (!Arrays.equals(chave.getEncoded(), chavePublica)) {
            throw new IllegalArgumentException("Chave pública mal codificada.");
        }

        int bits = ((RSAPublicKey) chave).getModulus().bitLength();
        if (bits < 3072 || bits > 4096) {
            throw new IllegalArgumentException(
                    "A chave tem de ter entre 3072 e 4096 bits.");
        }

        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(chave);
        verificador.update(dadosAssinados(nome, chavePublica));

        if (!verificador.verify(assinatura)) {
            throw new IllegalArgumentException(
                    "Prova de posse inválida: a assinatura não corresponde "
                    + "à chave pública enviada.");
        }

        return chave;
    }

    public static void validarNome(String nome) {
        if (nome == null || !nome.matches("[a-z0-9_-]{3,32}")) {
            throw new IllegalArgumentException("O nome tem de ter 3 a 32 "
                    + "caracteres: letras minúsculas, algarismos, _ ou -.");
        }
        if (RESERVADOS.contains(nome)) {
            throw new IllegalArgumentException("Nome reservado.");
        }
    }

    public byte[] codificar() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream saida = new DataOutputStream(bytes)) {
            saida.writeUTF(nome);
            saida.writeInt(chavePublica.length);
            saida.write(chavePublica);
            saida.writeInt(assinatura.length);
            saida.write(assinatura);
        }
        return bytes.toByteArray();
    }

    public static PedidoConta descodificar(byte[] dados) throws IOException {
        try (DataInputStream entrada =
                new DataInputStream(new ByteArrayInputStream(dados))) {
            String nome = entrada.readUTF();
            byte[] publica = lerCampo(entrada, 1024);
            byte[] assinatura = lerCampo(entrada, 1024);

            if (entrada.read() != -1) {
                throw new IOException("Dados adicionais no pedido.");
            }
            return new PedidoConta(nome, publica, assinatura);
        }
    }

    private static byte[] lerCampo(DataInputStream entrada, int maximo)
            throws IOException {
        int tamanho = entrada.readInt();
        // Validamos antes de reservar memória.
        if (tamanho < 1 || tamanho > maximo) {
            throw new IOException("Campo com tamanho inválido.");
        }
        byte[] campo = new byte[tamanho];
        entrada.readFully(campo);
        return campo;
    }

    /** Codificação sem ambiguidade: contexto, nome, chave. */
    private static byte[] dadosAssinados(String nome, byte[] publica)
            throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream saida = new DataOutputStream(bytes)) {
            saida.writeUTF(CONTEXTO);
            saida.writeUTF(nome);
            saida.writeInt(publica.length);
            saida.write(publica);
        }
        return bytes.toByteArray();
    }
}
