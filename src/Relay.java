import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

public class Relay {

    private static Set<String> registeredUsers =
            ConcurrentHashMap.newKeySet();

    private static Map<String, PrintWriter> clients =
            new ConcurrentHashMap<>();

    private static Map<String, String> publicKeys =
            new ConcurrentHashMap<>();

    public static void main(String[] args) {

        int port = 5000;

        try (ServerSocket server = new ServerSocket(port)) {

            System.out.println("Relay iniciado!");
            System.out.println("À espera de clientes...");

            while (true) {

                Socket client = server.accept();

                System.out.println("Novo cliente ligado!");

                Thread thread = new Thread(
                        () -> handleClient(client)
                );

                thread.start();
            }

        } catch (Exception e) {
            System.out.println("Erro no Relay: " + e.getMessage());
        }
    }

    public static void handleClient(Socket client) {

        String username = null;
        PrintWriter output = null;

        try {

            BufferedReader input = new BufferedReader(
                    new InputStreamReader(client.getInputStream())
            );

            output = new PrintWriter(
                    client.getOutputStream(), true
            );

            String message;

            while ((message = input.readLine()) != null) {

                System.out.println("Mensagem recebida: " + message);

                String[] parts = message.split("\\|", 4);

                // REGISTO
                if (parts[0].equals("REGISTER")) {

                    if (parts.length != 2 || username != null) {
                        output.println("ERROR|Pedido de registo inválido");
                        continue;
                    }

                    String requestedUsername = parts[1];

                    if (requestedUsername.isBlank()
                            || requestedUsername.contains("|")) {
                        output.println("ERROR|Nome inválido");
                        continue;
                    }

                    if (clients.putIfAbsent(
                            requestedUsername, output
                    ) == null) {

                        registeredUsers.add(requestedUsername);
                        username = requestedUsername;

                        System.out.println(
                                "Novo utilizador: " + username
                        );

                        output.println("OK|Utilizador registado");

                    } else {
                        output.println(
                                "ERROR|Utilizador já está online"
                        );
                    }
                }

                // LISTAR UTILIZADORES
                else if (parts[0].equals("LIST")) {

                    if (username == null) {
                        output.println("ERROR|Tens de estar registado");
                        continue;
                    }

                    List<String> users =
                            new ArrayList<>(registeredUsers);

                    Collections.sort(users);

                    output.println(
                            "USERS|" + String.join(",", users)
                    );
                }

                // PUBLICAR CHAVE PÚBLICA
                else if (parts[0].equals("PUBLISH_KEY")) {

                    if (username == null) {
                        output.println("ERROR|Tens de estar registado");
                        continue;
                    }

                    if (parts.length != 2 || parts[1].isBlank()) {
                        output.println("ERROR|Chave inválida");
                        continue;
                    }

                    try {

                        byte[] decoded =
                                Base64.getDecoder().decode(parts[1]);

                        if (decoded.length == 0) {
                            output.println("ERROR|Chave inválida");
                            continue;
                        }

                        publicKeys.put(username, parts[1]);

                        output.println(
                                "OK|Chave pública guardada"
                        );

                    } catch (IllegalArgumentException e) {

                        output.println(
                                "ERROR|Formato Base64 inválido"
                        );
                    }
                }

                // CONSULTAR CHAVE PÚBLICA
                else if (parts[0].equals("GET_KEY")) {

                    if (username == null) {
                        output.println("ERROR|Tens de estar registado");
                        continue;
                    }

                    if (parts.length != 2
                            || parts[1].isBlank()) {
                        output.println("ERROR|Pedido inválido");
                        continue;
                    }

                    String requestedUser = parts[1];

                    String publicKey =
                            publicKeys.get(requestedUser);

                    if (publicKey == null) {

                        output.println(
                                "ERROR|Chave pública não encontrada"
                        );

                    } else {

                        output.println(
                                "PUBLIC_KEY|" +
                                        requestedUser + "|" +
                                        publicKey
                        );
                    }
                }

                // ENVIAR MENSAGEM CIFRADA
                else if (parts[0].equals("SEND")) {

                    if (username == null) {
                        output.println("ERROR|Tens de estar registado");
                        continue;
                    }

                    if (parts.length != 4) {
                        output.println("ERROR|Formato inválido");
                        continue;
                    }

                    String recipient = parts[1];
                    String encryptedAESKey = parts[2];
                    String encryptedMessage = parts[3];

                    if (recipient.isBlank()
                            || encryptedAESKey.isBlank()
                            || encryptedMessage.isBlank()) {
                        output.println("ERROR|Dados inválidos");
                        continue;
                    }

                    PrintWriter recipientOutput =
                            clients.get(recipient);

                    if (recipientOutput == null) {

                        output.println(
                                "ERROR|Destinatário não está ligado"
                        );

                    } else {

                        recipientOutput.println(
                                "MESSAGE|" + username + "|" +
                                        encryptedAESKey + "|" +
                                        encryptedMessage
                        );

                        output.println("OK|Mensagem enviada");
                    }
                }

                // COMANDO DESCONHECIDO
                else {

                    output.println("ERROR|Comando desconhecido");
                }
            }

        } catch (Exception e) {

            System.out.println(
                    "Erro ao comunicar com cliente: " +
                            e.getMessage()
            );

        } finally {

            if (username != null && output != null) {

                clients.remove(username, output);

                System.out.println(
                        "Utilizador desligado: " + username
                );
            }

            try {
                client.close();
            } catch (Exception e) {
                System.out.println("Erro ao fechar ligação.");
            }
        }
    }
}
