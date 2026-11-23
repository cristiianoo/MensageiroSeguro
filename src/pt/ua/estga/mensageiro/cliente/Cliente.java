package pt.ua.estga.mensageiro.cliente;

import java.io.Console;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;

/**
 * Cliente de consola. A lógica de segurança está em SessaoCliente.
 *
 * Utilização: Cliente [nome]
 */
public final class Cliente {

    private Cliente() {
    }

    public static void main(String[] args) throws Exception {
        Console consola = System.console();

        if (consola == null) {
            throw new IllegalStateException(
                    "Executa o cliente num Terminal interativo.");
        }

        String utilizador = args.length == 1
                ? args[0]
                : consola.readLine("Nome de utilizador: ");

        if (utilizador == null || utilizador.isBlank()) {
            return;
        }
        utilizador = utilizador.strip();

        char[] palavraPasse;

        if (Contas.existe(utilizador)) {
            palavraPasse = consola.readPassword("Palavra-passe: ");
        } else {
            String resposta = consola.readLine("Não existe a conta %s neste "
                    + "computador. Criar conta nova? (s/n) ", utilizador);

            if (resposta == null || !resposta.strip().equalsIgnoreCase("s")) {
                return;
            }

            palavraPasse = criarConta(consola, utilizador);
            if (palavraPasse == null) {
                return;
            }
        }

        if (palavraPasse == null) {
            return;
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
            sessao = SessaoCliente.ligar(utilizador, palavraPasse, ouvinte);
        } catch (SessaoCliente.RelayRejeitado erro) {
            System.err.println(erro.getMessage());
            System.err.println("Detalhe: " + erro.getCause().getMessage());
            return;
        } catch (ConfiguracaoTLS.PalavraPasseIncorreta erro) {
            System.err.println("Palavra-passe incorreta.");
            return;
        } catch (java.net.ConnectException erro) {
            System.err.println("Não foi possível ligar ao relay. "
                    + "Está a correr?");
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

    /** Devolve a palavra-passe da conta criada, ou null se falhar. */
    private static char[] criarConta(Console consola, String nome) {
        char[] palavraPasse = consola.readPassword(
                "Escolhe uma palavra-passe (mínimo %d caracteres): ",
                Contas.MINIMO_PALAVRA_PASSE);
        char[] repetida = consola.readPassword("Repete a palavra-passe: ");

        try {
            if (palavraPasse == null || repetida == null) {
                return null;
            }
            if (!Arrays.equals(palavraPasse, repetida)) {
                System.err.println("As palavras-passe não coincidem.");
                Arrays.fill(palavraPasse, '\0');
                return null;
            }

            System.out.println("A criar a conta (gerar chaves e pedir "
                    + "o certificado à Autoridade)…");
            Contas.criar(nome, palavraPasse);
            System.out.println("Conta " + nome + " criada.");
            return palavraPasse;

        } catch (Exception erro) {
            System.err.println("Não foi possível criar a conta: "
                    + erro.getMessage());
            Arrays.fill(palavraPasse, '\0');
            return null;
        } finally {
            if (repetida != null) {
                Arrays.fill(repetida, '\0');
            }
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
