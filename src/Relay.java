import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Relay do Mensageiro Seguro.
 *
 * Protocolo (texto, UTF-8, uma mensagem por linha, campos separados por '|'):
 *
 *   Cliente -> Relay                         Relay -> Cliente
 *   REGISTER|username                        OK|... | ERROR|...
 *   LIST                                     USERS|a,b,c
 *   PUBLISH_KEY|chavePublicaBase64(X.509)    OK|... | ERROR|...
 *   GET_KEY|username                         PUBLIC_KEY|username|chaveBase64
 *   SEND|destinatario|payloadBase64          OK|... | ERROR|...
 *                                            MESSAGE|remetente|payloadBase64
 *
 * O payload é opaco para o relay: o formato (IV, chave cifrada, criptograma,
 * assinatura, ...) é definido pelo cliente e nunca é interpretado aqui.
 */
public class Relay {

    private static final int DEFAULT_PORT = 5000;
    private static final int MAX_CONNECTIONS = 200;
    private static final int MAX_LINE_BYTES = 64 * 1024;
    private static final int MAX_KEY_CHARS = 8 * 1024;
    private static final int REGISTER_TIMEOUT_MS = 30_000;

    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_.-]{3,32}");
    private static final String[] KEY_ALGORITHMS = {"RSA", "EC", "Ed25519"};

    private static final Set<String> registeredUsers = ConcurrentHashMap.newKeySet();
    private static final Map<String, Session> online = new ConcurrentHashMap<>();
    private static final Map<String, String> publicKeys = new ConcurrentHashMap<>();
    private static final AtomicInteger connections = new AtomicInteger();

    // ---------------------------------------------------------------- sessão

    private static final class Session {
        final Socket socket;
        private final BufferedWriter out;
        volatile String username;

        Session(Socket socket) throws IOException {
            this.socket = socket;
            this.out = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        }

        /** Escrita serializada: várias threads podem enviar para a mesma sessão. */
        synchronized boolean send(String line) {
            try {
                out.write(line);
                out.write('\n');
                out.flush();
                return true;
            } catch (IOException e) {
                close();
                return false;
            }
        }

        void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static final class LineTooLongException extends IOException {
        private static final long serialVersionUID = 1L;

        LineTooLongException() {
            super("Linha demasiado longa");
        }
    }

    // ------------------------------------------------------------------ main

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        ExecutorService pool = Executors.newCachedThreadPool();

        try (ServerSocket server = new ServerSocket(port)) {
            log("Relay iniciado na porta " + port);

            while (true) {
                Socket socket = server.accept();

                if (connections.incrementAndGet() > MAX_CONNECTIONS) {
                    connections.decrementAndGet();
                    reject(socket);
                    continue;
                }

                pool.execute(() -> {
                    try {
                        handleClient(socket);
                    } finally {
                        connections.decrementAndGet();
                    }
                });
            }
        }
    }

    private static void reject(Socket socket) {
        try (socket) {
            socket.getOutputStream()
                    .write("ERROR|Relay cheio\n".getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
    }

    // ------------------------------------------------------------ ligação

    private static void handleClient(Socket socket) {
        Session session = null;

        try {
            // Quem não se regista a tempo é desligado (evita ligações penduradas).
            socket.setSoTimeout(REGISTER_TIMEOUT_MS);
            session = new Session(socket);
            InputStream in = new BufferedInputStream(socket.getInputStream());

            String line;
            while ((line = readLine(in)) != null) {
                process(session, line);
            }

        } catch (LineTooLongException e) {
            if (session != null) session.send("ERROR|Linha demasiado longa");
            log("Ligação terminada: linha demasiado longa");
        } catch (SocketTimeoutException e) {
            if (session != null) session.send("ERROR|Tempo de registo excedido");
            log("Ligação terminada: sem registo a tempo");
        } catch (IOException e) {
            log("Ligação terminada: " + e.getMessage());
        } finally {
            if (session != null) {
                String user = session.username;
                if (user != null) {
                    online.remove(user, session);
                    log("Utilizador desligado: " + user);
                }
                session.close();
            } else {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /** Lê uma linha terminada em '\n' com limite de tamanho. null = fim da ligação. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
        int b;

        while ((b = in.read()) != -1) {
            if (b == '\n') {
                byte[] bytes = buf.toByteArray();
                int len = bytes.length;
                if (len > 0 && bytes[len - 1] == '\r') len--;
                return new String(bytes, 0, len, StandardCharsets.UTF_8);
            }
            if (buf.size() >= MAX_LINE_BYTES) {
                throw new LineTooLongException();
            }
            buf.write(b);
        }
        return null;
    }

    // ------------------------------------------------------------ comandos

    private static void process(Session s, String line) {
        String[] p = line.split("\\|", 3);

        if (p[0].equals("REGISTER")) {
            register(s, p);
            return;
        }

        if (s.username == null) {
            s.send("ERROR|Tens de estar registado");
            return;
        }

        switch (p[0]) {
            case "LIST":
                list(s, p);
                break;
            case "PUBLISH_KEY":
                publishKey(s, p);
                break;
            case "GET_KEY":
                getKey(s, p);
                break;
            case "SEND":
                send(s, p);
                break;
            default:
                s.send("ERROR|Comando desconhecido");
        }
    }

    private static void register(Session s, String[] p) {
        if (s.username != null || p.length != 2) {
            s.send("ERROR|Pedido de registo inválido");
            return;
        }

        String name = p[1];

        if (!USERNAME.matcher(name).matches()) {
            s.send("ERROR|Nome inválido (3-32 caracteres: letras, números, '_', '.', '-')");
            return;
        }

        if (online.putIfAbsent(name, s) != null) {
            s.send("ERROR|Utilizador já está online");
            return;
        }

        s.username = name;
        registeredUsers.add(name);

        try {
            s.socket.setSoTimeout(0); // já registado: pode ficar à espera de mensagens
        } catch (IOException ignored) {
        }

        log("Novo utilizador: " + name);
        s.send("OK|Utilizador registado");
    }

    private static void list(Session s, String[] p) {
        if (p.length != 1) {
            s.send("ERROR|Pedido inválido");
            return;
        }
        List<String> users = new ArrayList<>(registeredUsers);
        Collections.sort(users);
        s.send("USERS|" + String.join(",", users));
    }

    private static void publishKey(Session s, String[] p) {
        if (p.length != 2) {
            s.send("ERROR|Chave inválida");
            return;
        }

        byte[] der = decodePublicKey(p[1]);
        if (der == null) {
            s.send("ERROR|Chave inválida");
            return;
        }

        String canonical = Base64.getEncoder().encodeToString(der);

        // A chave de um utilizador não pode ser substituída por outra.
        String previous = publicKeys.putIfAbsent(s.username, canonical);
        if (previous != null && !previous.equals(canonical)) {
            log("ALERTA: tentativa de substituir a chave de " + s.username);
            s.send("ERROR|Este utilizador já tem outra chave pública associada");
            return;
        }

        s.send("OK|Chave pública guardada");
    }

    private static void getKey(Session s, String[] p) {
        if (p.length != 2 || !USERNAME.matcher(p[1]).matches()) {
            s.send("ERROR|Pedido inválido");
            return;
        }

        String key = publicKeys.get(p[1]);
        if (key == null) {
            s.send("ERROR|Chave pública não encontrada");
        } else {
            s.send("PUBLIC_KEY|" + p[1] + "|" + key);
        }
    }

    private static void send(Session s, String[] p) {
        if (p.length != 3 || p[2].isBlank() || !USERNAME.matcher(p[1]).matches()) {
            s.send("ERROR|Formato inválido");
            return;
        }

        String recipient = p[1];
        String payload = p[2];

        if (recipient.equals(s.username)) {
            s.send("ERROR|Não podes enviar mensagens a ti próprio");
            return;
        }

        Session target = online.get(recipient);
        if (target == null) {
            s.send("ERROR|Destinatário não está ligado");
            return;
        }

        // O remetente é sempre o utilizador desta sessão: o cliente não o pode forjar aqui.
        if (target.send("MESSAGE|" + s.username + "|" + payload)) {
            log(s.username + " -> " + recipient + " (" + payload.length() + " caracteres)");
            s.send("OK|Mensagem enviada");
        } else {
            s.send("ERROR|Falha na entrega");
        }
    }

    // ------------------------------------------------------------ auxiliares

    /** Devolve os bytes DER da chave se for uma chave pública X.509 válida; senão null. */
    private static byte[] decodePublicKey(String base64) {
        if (base64.isBlank() || base64.length() > MAX_KEY_CHARS) return null;

        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            return null;
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        for (String algorithm : KEY_ALGORITHMS) {
            try {
                KeyFactory.getInstance(algorithm).generatePublic(spec);
                return der;
            } catch (GeneralSecurityException ignored) {
            }
        }
        return null;
    }

    private static void log(String message) {
        System.out.println(message);
    }
}