package pt.ua.estga.mensageiro.relay;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

import pt.ua.estga.mensageiro.protocolo.Protocolo;

public final class SessoesRelay {

    private final ConcurrentHashMap<String, DataOutputStream> ligacoes =
            new ConcurrentHashMap<>();

    public boolean adicionar(String identidade, DataOutputStream saida) {
        // Nesta versão permitimos uma ligação por utilizador.
        return ligacoes.putIfAbsent(identidade, saida) == null;
    }

    public void remover(String identidade, DataOutputStream saida) {
        // Uma ligação antiga não deve remover uma ligação nova.
        ligacoes.remove(identidade, saida);
    }

    public void encaminhar(String remetente, byte[] pedido)
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

        DataOutputStream destino = ligacoes.get(destinatario);

        if (destino == null) {
            throw new IOException("O destinatário não está ligado.");
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        try (DataOutputStream entrega = new DataOutputStream(bytes)) {
            // O remetente vem da sessão TLS autenticada.
            entrega.writeUTF(remetente);
            entrega.writeInt(envelope.length);
            entrega.write(envelope);
        }

        synchronized (destino) {
            Protocolo.enviar(destino, Protocolo.ENTREGA,
                    bytes.toByteArray());
        }
    }
}
