package pt.ua.estga.mensageiro.relay;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Guarda em disco as entregas para destinatários desligados.
 *
 * Cada entrega fica num ficheiro próprio, dentro da caixa do destinatário.
 * O conteúdo é a trama ENTREGA (remetente + envelope), já cifrada e
 * assinada pelo cliente: o relay não consegue ler nem alterar a mensagem
 * sem que o destinatário o detete.
 */
public final class ArmazemMensagens {

    // Limite por caixa, para um remetente não encher o disco do relay.
    private static final int MAX_POR_CAIXA = 200;

    private final Path raiz;

    // Um trinco por caixa: guardar e levantar não se cruzam.
    private final ConcurrentHashMap<String, Object> trincos =
            new ConcurrentHashMap<>();

    public ArmazemMensagens(Path raiz) throws IOException {
        this.raiz = raiz;
        Files.createDirectories(raiz);
    }

    public void guardar(String destinatario, byte[] entrega)
            throws IOException {

        synchronized (trinco(destinatario)) {
            Path caixa = raiz.resolve(destinatario);
            Files.createDirectories(caixa);

            if (contar(caixa) >= MAX_POR_CAIXA) {
                throw new IOException("Caixa do destinatário cheia.");
            }

            // O prefixo temporal mantém a ordem de chegada.
            String nome = String.format("%019d-%s",
                    System.currentTimeMillis(), UUID.randomUUID());

            // Escrita atómica: nunca fica um ficheiro meio escrito.
            Path temporario = caixa.resolve(nome + ".tmp");
            Files.write(temporario, entrega);
            Files.move(temporario, caixa.resolve(nome + ".msg"),
                    StandardCopyOption.ATOMIC_MOVE);
        }
    }

    /**
     * Entrega as mensagens pendentes de um utilizador, por ordem.
     * Cada ficheiro só é apagado depois de a entrega ser escrita.
     *
     * @return número de mensagens entregues
     */
    public int levantar(String destinatario, Entregador entregador)
            throws IOException {

        synchronized (trinco(destinatario)) {
            Path caixa = raiz.resolve(destinatario);

            if (!Files.isDirectory(caixa)) {
                return 0;
            }

            List<Path> pendentes = new ArrayList<>();

            try (Stream<Path> ficheiros = Files.list(caixa)) {
                ficheiros.filter(f -> f.toString().endsWith(".msg"))
                        .sorted()
                        .forEach(pendentes::add);
            }

            int entregues = 0;

            for (Path ficheiro : pendentes) {
                entregador.entregar(Files.readAllBytes(ficheiro));
                Files.delete(ficheiro);
                entregues++;
            }

            return entregues;
        }
    }

    private Object trinco(String destinatario) {
        return trincos.computeIfAbsent(destinatario, d -> new Object());
    }

    private static long contar(Path caixa) throws IOException {
        try (Stream<Path> ficheiros = Files.list(caixa)) {
            return ficheiros.filter(f -> f.toString().endsWith(".msg"))
                    .count();
        }
    }

    @FunctionalInterface
    public interface Entregador {
        void entregar(byte[] entrega) throws IOException;
    }
}
