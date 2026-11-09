package pt.ua.estga.mensageiro.protocolo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public final class Protocolo {

    public static final int REGISTAR = 1;
    public static final int PROCURAR = 2;
    public static final int ENVIAR = 3;
    public static final int ENTREGA = 102;

    public static final int SUCESSO = 100;
    public static final int CERTIFICADO = 101;
    public static final int ERRO = 199;

    public static final int TAMANHO_MAXIMO = 64 * 1024;

    private Protocolo() {
    }

    public record Mensagem(int tipo, byte[] dados) {

        public Mensagem {
            // Guardamos uma cópia para os dados não mudarem por fora.
            dados = dados.clone();
        }

        @Override
        public byte[] dados() {
            return dados.clone();
        }
    }

    public static void enviar(
            DataOutputStream saida,
            int tipo,
            byte[] dados) throws IOException {

        if (dados.length > TAMANHO_MAXIMO) {
            throw new IOException("Mensagem demasiado grande.");
        }

        saida.writeInt(tipo);
        saida.writeInt(dados.length);
        saida.write(dados);
        saida.flush();
    }

    public static Mensagem receber(DataInputStream entrada)
            throws IOException {

        int tipo = entrada.readInt();
        int tamanho = entrada.readInt();

        // Validamos antes de reservar memória.
        if (tamanho < 0 || tamanho > TAMANHO_MAXIMO) {
            throw new IOException("Comprimento de mensagem inválido.");
        }

        byte[] dados = new byte[tamanho];

        // Uma leitura simples pode trazer só parte da mensagem.
        entrada.readFully(dados);

        return new Mensagem(tipo, dados);
    }
}
