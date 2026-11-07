import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) {

        try {

            Socket socket = new Socket("localhost", 5000);

            PrintWriter output = new PrintWriter(
                    socket.getOutputStream(), true
            );

            BufferedReader input = new BufferedReader(
                    new InputStreamReader(socket.getInputStream())
            );

            // THREAD PARA RECEBER MENSAGENS
            Thread receiver = new Thread(() -> {

                try {

                    String response;

                    while ((response = input.readLine()) != null) {

                        if (response.startsWith("MESSAGE|")) {

                            String[] parts =
                                    response.split("\\|", 4);

                            if (parts.length == 4) {

                                System.out.println(
                                        "\nMensagem cifrada recebida de: "
                                                + parts[1]
                                );

                                System.out.println(
                                        "Chave AES protegida: "
                                                + parts[2]
                                );

                                System.out.println(
                                        "Mensagem cifrada: "
                                                + parts[3]
                                );
                            }

                        } else {

                            System.out.println(
                                    "\nRelay: " + response
                            );
                        }

                        System.out.print("Comando: ");
                    }

                } catch (Exception e) {

                    System.out.println(
                            "\nLigação terminada."
                    );
                }
            });

            receiver.start();

            Scanner scanner = new Scanner(System.in);

            System.out.println("=== MENSAGEIRO SEGURO ===");
            System.out.println("Escreve /quit para sair.");

            while (true) {

                System.out.print("Comando: ");

                String command = scanner.nextLine();

                if (command.equalsIgnoreCase("/quit")) {
                    break;
                }

                output.println(command);
            }

            socket.close();

            System.out.println("A desligar...");

        } catch (Exception e) {

            System.out.println(
                    "Erro: " + e.getMessage()
            );
        }
    }
}
