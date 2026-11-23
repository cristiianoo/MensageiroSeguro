package pt.ua.estga.mensageiro.relay;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import pt.ua.estga.mensageiro.protocolo.Protocolo;

public final class SessoesRelay {

    /** Resultado de um envio: entregue de imediato ou guardado. */
    public enum Resultado { ENTREGUE, GUARDADO }

    /** Pedido ENVIAR já validado. */
    public record PedidoEnvio(String destinatario, byte[] entrega) {
    }

    private final ConcurrentHashMap<String, DataOutputStream> ligacoes =
            new ConcurrentHashMap<>();

    private final ArmazemMensagens armazem;

    public SessoesRelay(ArmazemMensagens armazem) {
        this.armazem = armazem;
    }

    public boolean adicionar(String identidade, DataOutputStream saida) {
        // Nesta versão permitimos uma ligação por utilizador.
        return ligacoes.putIfAbsent(identidade, saida) == null;
    }

    public void remover(String identidade, DataOutputStream saida) {
        // Uma ligação antiga não deve remover uma ligação nova.
        ligacoes.remove(identidade, saida);
    }

    /**
     * Valida um pedido ENVIAR e prepara a trama ENTREGA.
     * O remetente vem da sessão TLS autenticada, nunca do pedido.
     */
    public static PedidoEnvio interpretar(String remetente, byte[] pedido)
            throws IOException {

        String destinatario;
        byte[] envelope;

        try (DataInputStream entrada = new DataInputStream(
                new ByteArrayInputStream(pedido))) {
            destinatario = entrada.readUTF();

            if (!destinatario.matches("[a-z0-9_-]{1,32}")) {
                throw new IOException("Destinatário inválido.");
            }

            int tamanho = entrada.readInt();

            if (tamanho < 1 || tamanho > 60 * 1024) {
                throw new IOException("Tamanho de envelope inválido.");
            }

            envelope = new byte[tamanho];
            entrada.readFully(envelope);

            if (entrada.read() != -1) {
                throw new IOException("Dados adicionais no pedido.");
            }
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (DataOutputStream entrega = new DataOutputStream(bytes)) {
            entrega.writeUTF(remetente);
            entrega.writeInt(envelope.length);
            entrega.write(envelope);
        }

        return new PedidoEnvio(destinatario, bytes.toByteArray());
    }

    /**
     * Entrega de imediato se o destinatário estiver ligado; caso contrário
     * guarda para levantamento posterior.
     *
     * @param registado indica se o destinatário existe no diretório
     */
    public Resultado encaminhar(
            PedidoEnvio pedido, Predicate<String> registado)
            throws IOException {

        // Não guardamos mensagens para quem nunca se registou.
        if (!registado.test(pedido.destinatario())) {
            throw new IOException("Destinatário desconhecido.");
        }

        DataOutputStream destino = ligacoes.get(pedido.destinatario());

        if (destino != null) {
            try {
                enviarEntrega(destino, pedido.entrega());
                return Resultado.ENTREGUE;
            } catch (IOException ligacaoCaiu) {
                // A ligação caiu entretanto: passamos a guardar.
            }
        }

        armazem.guardar(pedido.destinatario(), pedido.entrega());
        return Resultado.GUARDADO;
    }

    /** Entrega ao próprio utilizador as mensagens guardadas para ele. */
    public int levantar(String identidade, DataOutputStream saida)
            throws IOException {
        return armazem.levantar(identidade,
                entrega -> enviarEntrega(saida, entrega));
    }

    private static void enviarEntrega(DataOutputStream destino, byte[] dados)
            throws IOException {
        synchronized (destino) {
            Protocolo.enviar(destino, Protocolo.ENTREGA, dados);
        }
    }
}
