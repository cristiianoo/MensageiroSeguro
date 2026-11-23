package pt.ua.estga.mensageiro.cliente;

import java.io.Console;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;

/** Cliente de consola. A lógica de segurança está em SessaoCliente. */
public final class Cliente {

    private Cliente() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1
                || !SessaoCliente.UTILIZADORES.contains(args[0])) {
            System.err.println("Utilização: Cliente <joao|cristiano>");
            return;
        }

        String utilizador = args[0];
        Console consola = System.console();

        if (consola == null) {
            throw new IllegalStateException(
                    "Executa o cliente num Terminal interativo.");
        }

        char[] passeIdentidade = consola.readPassword(
                "Palavra-passe da identidade de %s: ", utilizador);
        char[] passeConfianca = consola.readPassword(
                "Palavra-passe do ficheiro de confiança: ");

        if (passeIdentidade == null || passeConfianca == null) {
            if (passeIdentidade != null) {
                Arrays.fill(passeIdentidade, '\0');
            }
            throw new IllegalStateException("Leitura cancelada.");
        }

        SessaoCliente.Ouvinte ouvinte = new SessaoCliente.Ouvinte() {
            @Override
            public void mensagemVerificada(String remetente, String texto) {
                System.out.println("\nMensagem verificada de "
                        + remetente + ": " + texto);
            }

            @Override
            public void mensagemRejeitada(String motivo) {
                System.err.println("\nMensagem rejeitada: " + motivo);
            }

            @Override
            public void ligacaoTerminada(String motivo) {
                System.err.println("\nLigação terminada: " + motivo);
            }
        };

        SessaoCliente sessao;

        try {
            sessao = SessaoCliente.ligar(
                    utilizador, passeIdentidade, passeConfianca, ouvinte);
        } catch (SessaoCliente.RelayRejeitado erro) {
            System.err.println(erro.getMessage());
            System.err.println("Detalhe: " + erro.getCause().getMessage());
            return;
        } catch (ConfiguracaoTLS.PalavraPasseIncorreta erro) {
            System.err.println(erro.getMessage());
            return;
        }

        try (sessao) {
            System.out.println("Ligação TLS estabelecida: "
                    + sessao.protocolo());

            System.out.println(sessao.registar());

            // Ao ligar, recolhemos o que chegou enquanto estávamos fora.
            System.out.println(sessao.levantar());

            executar(sessao, consola);
        }
    }

    private static void executar(SessaoCliente sessao, Console consola) {
        System.out.println("Comandos: procurar <nome>, enviar <nome>, "
                + "levantar, sair");

        while (sessao.ativa()) {
            String comando = consola.readLine("> ");

            if (comando == null || comando.equals("sair")
                    || !sessao.ativa()) {
                break;
            }

            try {
                if (comando.startsWith("procurar ")) {
                    X509Certificate certificado =
                            sessao.procurar(comando.substring(9).trim());

                    System.out.println("Certificado validado: "
                            + certificado.getSubjectX500Principal().getName());

                } else if (comando.startsWith("enviar ")) {
                    String nome = comando.substring(7).trim();

                    // Validamos o destinatário antes de pedir o texto.
                    sessao.procurar(nome);
                    String mensagem = consola.readLine("Mensagem: ");

                    if (mensagem != null && sessao.ativa()) {
                        System.out.println(sessao.enviar(nome, mensagem));
                    }

                } else if (comando.equals("levantar")) {
                    System.out.println(sessao.levantar());

                } else {
                    System.out.println("Usa: procurar <nome>, "
                            + "enviar <nome>, levantar ou sair");
                }
            } catch (Exception erro) {
                System.err.println("Operação recusada: " + erro.getMessage());
            }
        }
    }
}
