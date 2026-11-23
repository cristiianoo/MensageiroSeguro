package pt.ua.estga.mensageiro.cliente;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import pt.ua.estga.mensageiro.seguranca.ConfiguracaoTLS;

/**
 * Interface gráfica do cliente (Swing, só JDK).
 *
 * Toda a segurança está em SessaoCliente; esta classe só mostra.
 * Regras: pedidos ao relay nunca correm na thread da interface,
 * e o texto vindo da rede só é mostrado em componentes sem HTML.
 *
 * Utilização: ClienteGUI [nome]
 */
public final class ClienteGUI implements SessaoCliente.Ouvinte {

    private static final DateTimeFormatter HORA =
            DateTimeFormatter.ofPattern("HH:mm");

    private static final Color VERDE = new Color(0x1B6E3A);
    private static final Color VERMELHO = new Color(0xB3261E);

    // Um pedido de cada vez, numa thread própria, por ordem.
    private final ExecutorService fundo = Executors.newSingleThreadExecutor(
            Thread.ofPlatform().daemon().name("pedidos-gui").factory());

    private final JFrame janela = new JFrame("Mensageiro Seguro");
    private final DefaultListModel<String> contactos = new DefaultListModel<>();
    private final JList<String> listaContactos = new JList<>(contactos);
    private final JLabel cabecalho = semHtml(new JLabel(" "));
    private final JTextArea conversa = areaTexto();
    private final JTextArea eventos = areaTexto();
    private final JTextField campoTexto = new JTextField();
    private final JButton botaoEnviar = new JButton("Enviar");
    private final JButton botaoLevantar = new JButton("Levantar");
    private final JButton botaoAdicionar = new JButton("+ Contacto");
    private final JLabel estado = semHtml(new JLabel(" "));

    // Só acedidos na thread da interface.
    private final Map<String, StringBuilder> conversas = new HashMap<>();
    private final Set<String> porLer = new HashSet<>();

    private volatile SessaoCliente sessao;

    private ClienteGUI() {
    }

    public static void main(String[] args) {
        String sugerido = args.length == 1 ? args[0] : null;

        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(
                        UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignorado) {
                // Fica o aspeto por omissão do Swing.
            }

            new ClienteGUI().pedirCredenciais(sugerido, false, null);
        });
    }

    // ------------------------------------------------------------------
    // Entrada
    // ------------------------------------------------------------------

    private void pedirCredenciais(String sugerido, boolean criarSugerido,
            String erroAnterior) {

        JTextField campoNome = new JTextField(sugerido == null ? "" : sugerido, 18);
        JPasswordField campoPasse = new JPasswordField(18);
        JPasswordField campoRepetir = new JPasswordField(18);
        JCheckBox criar = new JCheckBox("Criar conta nova", criarSugerido);
        JLabel rotuloRepetir = new JLabel("Repetir palavra-passe:");

        Runnable atualizar = () -> {
            campoRepetir.setEnabled(criar.isSelected());
            rotuloRepetir.setEnabled(criar.isSelected());
        };
        criar.addActionListener(e -> atualizar.run());
        atualizar.run();

        JPanel painel = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 4, 4, 4);
        g.anchor = GridBagConstraints.WEST;

        int linha = 0;
        if (erroAnterior != null) {
            JLabel erro = semHtml(new JLabel(erroAnterior));
            erro.setForeground(VERMELHO);
            g.gridx = 0;
            g.gridy = linha++;
            g.gridwidth = 2;
            painel.add(erro, g);
            g.gridwidth = 1;
        }

        adicionarCampo(painel, g, linha++, new JLabel("Nome de utilizador:"),
                campoNome);
        adicionarCampo(painel, g, linha++, new JLabel("Palavra-passe:"),
                campoPasse);
        adicionarCampo(painel, g, linha++, rotuloRepetir, campoRepetir);
        g.gridx = 1;
        g.gridy = linha;
        painel.add(criar, g);

        JOptionPane pergunta = new JOptionPane(painel,
                JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
        JDialog dialogo = pergunta.createDialog("Mensageiro Seguro: entrar");

        // O JOptionPane põe o foco no OK; passamos para o primeiro campo
        // por preencher.
        JComponent primeiro = campoNome.getText().isEmpty()
                ? campoNome : campoPasse;
        dialogo.addWindowFocusListener(new WindowAdapter() {
            private boolean primeira = true;

            @Override
            public void windowGainedFocus(WindowEvent e) {
                if (primeira) {
                    primeira = false;
                    primeiro.requestFocusInWindow();
                }
            }
        });

        dialogo.setVisible(true);   // modal: espera pela resposta
        dialogo.dispose();

        int opcao = pergunta.getValue() instanceof Integer valor
                ? valor : JOptionPane.CLOSED_OPTION;

        // getPassword devolve uma cópia em char[]; os campos são limpos já.
        char[] palavraPasse = campoPasse.getPassword();
        char[] repetida = campoRepetir.getPassword();
        campoPasse.setText("");
        campoRepetir.setText("");

        String utilizador = campoNome.getText().strip();
        boolean contaNova = criar.isSelected();
        boolean iguais = Arrays.equals(palavraPasse, repetida);
        Arrays.fill(repetida, '\0');

        if (opcao != JOptionPane.OK_OPTION) {
            Arrays.fill(palavraPasse, '\0');
            System.exit(0);
        }

        String problema = null;
        if (utilizador.isEmpty() || palavraPasse.length == 0) {
            problema = "Preenche o nome e a palavra-passe.";
        } else if (contaNova && !iguais) {
            problema = "As palavras-passe não coincidem.";
        } else if (!contaNova && !Contas.existe(utilizador)) {
            problema = "Não existe a conta " + utilizador
                    + " neste computador. Marca «Criar conta nova».";
        }

        if (problema != null) {
            Arrays.fill(palavraPasse, '\0');
            pedirCredenciais(utilizador, contaNova, problema);
            return;
        }

        // Uma janela visível durante a espera: sem nenhuma, o AWT
        // termina o programa enquanto as chaves ainda estão a ser geradas.
        JDialog aguarde = new JDialog((JFrame) null, "Mensageiro Seguro");
        JLabel textoAguarde = new JLabel(contaNova
                ? "A criar a conta: a gerar as chaves e a pedir o certificado…"
                : "A abrir a conta e a ligar ao relay…");
        textoAguarde.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));
        aguarde.add(textoAguarde);
        aguarde.pack();
        aguarde.setLocationRelativeTo(null);
        aguarde.setVisible(true);

        // Gerar chaves, TLS e ler o PKCS12 não podem bloquear a interface.
        fundo.submit(() -> {
            boolean criada = false;
            try {
                if (contaNova) {
                    Contas.criar(utilizador, palavraPasse);
                    criada = true;
                }

                // ligar apaga a palavra-passe antes de retornar.
                SessaoCliente nova =
                        SessaoCliente.ligar(utilizador, palavraPasse, this);
                sessao = nova;

                String protocolo = nova.protocolo();
                String registo = nova.registar();
                boolean foiCriada = criada;

                SwingUtilities.invokeLater(() -> {
                    abrirJanela(utilizador);
                    aguarde.dispose();
                    if (foiCriada) {
                        evento("Conta criada: chaves geradas neste computador "
                                + "e certificado emitido pela Autoridade.");
                    }
                    evento("Ligação TLS estabelecida: " + protocolo
                            + " (autenticação mútua)");
                    evento(registo);
                    mostrarEstado("Ligado ao relay como " + utilizador
                            + " · " + protocolo, VERDE);

                    // Ao ligar, recolhemos o que chegou enquanto
                    // estávamos fora (já com a janela aberta).
                    levantar();
                });

            } catch (SessaoCliente.RelayRejeitado erro) {
                SwingUtilities.invokeLater(() -> {
                    aguarde.dispose();
                    JOptionPane.showMessageDialog(null,
                            semHtml(new JLabel(erro.getMessage())),
                            "Relay rejeitado", JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                });
            } catch (Exception erro) {
                Arrays.fill(palavraPasse, '\0');
                SessaoCliente aberta = sessao;
                if (aberta != null) {
                    aberta.close();
                    sessao = null;
                }
                // Se a conta já foi criada, a próxima tentativa é entrar.
                boolean voltarACriar = contaNova && !criada;
                SwingUtilities.invokeLater(() -> {
                    // Na mesma tarefa da interface: o diálogo abre logo
                    // a seguir, por isso nunca ficamos sem janelas.
                    aguarde.dispose();
                    pedirCredenciais(utilizador, voltarACriar, descrever(erro));
                });
            }
        });
    }

    private static void adicionarCampo(JPanel painel, GridBagConstraints g,
            int linha, JLabel rotulo, JComponent campo) {
        g.gridx = 0;
        g.gridy = linha;
        painel.add(rotulo, g);
        g.gridx = 1;
        painel.add(campo, g);
    }

    // ------------------------------------------------------------------
    // Janela principal
    // ------------------------------------------------------------------

    private void abrirJanela(String utilizador) {
        janela.setTitle("Mensageiro Seguro: " + utilizador);
        janela.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        janela.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                sair();
            }
        });

        for (String nome : Contas.contactos(utilizador)) {
            contactos.addElement(nome);
        }

        listaContactos.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        listaContactos.setCellRenderer(new RenderizadorContacto());
        listaContactos.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                selecionarContacto(listaContactos.getSelectedValue());
            }
        });

        botaoLevantar.addActionListener(e -> levantar());
        botaoAdicionar.addActionListener(e -> adicionarContacto());

        JPanel esquerda = new JPanel(new BorderLayout(0, 6));
        esquerda.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 4));
        esquerda.add(new JLabel("Contactos"), BorderLayout.NORTH);
        esquerda.add(new JScrollPane(listaContactos), BorderLayout.CENTER);
        JPanel botoes = new JPanel(new java.awt.GridLayout(2, 1, 0, 6));
        botoes.add(botaoAdicionar);
        botoes.add(botaoLevantar);
        esquerda.add(botoes, BorderLayout.SOUTH);
        esquerda.setPreferredSize(new Dimension(170, 0));

        campoTexto.addActionListener(e -> enviar());
        botaoEnviar.addActionListener(e -> enviar());

        JPanel escrita = new JPanel(new BorderLayout(6, 0));
        escrita.add(campoTexto, BorderLayout.CENTER);
        escrita.add(botaoEnviar, BorderLayout.EAST);

        cabecalho.setFont(cabecalho.getFont().deriveFont(Font.BOLD));

        JPanel direita = new JPanel(new BorderLayout(0, 6));
        direita.setBorder(BorderFactory.createEmptyBorder(8, 4, 8, 8));
        direita.add(cabecalho, BorderLayout.NORTH);
        direita.add(new JScrollPane(conversa), BorderLayout.CENTER);
        direita.add(escrita, BorderLayout.SOUTH);

        JSplitPane topo = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT, esquerda, direita);
        topo.setBorder(null);

        eventos.setRows(5);
        JScrollPane painelEventos = new JScrollPane(eventos);
        painelEventos.setBorder(BorderFactory.createTitledBorder(
                "Eventos de segurança"));

        JSplitPane centro = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, topo, painelEventos);
        centro.setResizeWeight(0.75);
        centro.setBorder(null);

        estado.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        janela.getContentPane().add(centro, BorderLayout.CENTER);
        janela.getContentPane().add(estado, BorderLayout.SOUTH);
        janela.setSize(760, 520);
        janela.setLocationByPlatform(true);

        definirEscritaAtiva(false);
        janela.setVisible(true);

        if (contactos.isEmpty()) {
            cabecalho.setText("Ainda não tens contactos: "
                    + "usa «+ Contacto» e escreve o nome de alguém.");
        } else {
            listaContactos.setSelectedIndex(0);
        }
    }

    /** Pede um nome e só o junta se o relay tiver um certificado válido. */
    private void adicionarContacto() {
        String nome = JOptionPane.showInputDialog(janela,
                "Nome de utilizador do contacto:", "Adicionar contacto",
                JOptionPane.PLAIN_MESSAGE);

        if (nome == null || nome.isBlank()) {
            return;
        }
        String contacto = nome.strip().toLowerCase();

        if (contacto.equals(sessao.utilizador())) {
            evento("Não te podes adicionar a ti próprio.");
            return;
        }

        emFundo(() -> sessao.procurar(contacto), certificado -> {
            juntarContacto(contacto);
            listaContactos.setSelectedValue(contacto, true);
            evento("Contacto adicionado: " + contacto
                    + " (certificado validado pela CA).");
        }, erro -> evento("Não foi possível adicionar " + contacto + ": "
                + descrever(erro)));
    }

    private void juntarContacto(String contacto) {
        if (!contactos.contains(contacto)) {
            contactos.addElement(contacto);
        }
        try {
            Contas.adicionarContacto(sessao.utilizador(), contacto);
        } catch (java.io.IOException erro) {
            evento("Não foi possível guardar o contacto: " + erro.getMessage());
        }
    }

    private void selecionarContacto(String nome) {
        if (nome == null) {
            return;
        }

        porLer.remove(nome);
        listaContactos.repaint();
        conversa.setText(conversas.computeIfAbsent(
                nome, k -> new StringBuilder()).toString());

        cabecalho.setForeground(Color.DARK_GRAY);
        cabecalho.setText(nome + ": a validar certificado…");
        definirEscritaAtiva(false);

        // Mostramos a impressão digital para comparação fora de banda.
        emFundo(() -> sessao.procurar(nome), certificado -> {
            if (!nome.equals(listaContactos.getSelectedValue())) {
                return;
            }
            cabecalho.setForeground(VERDE);
            cabecalho.setText(nome + " · certificado validado pela CA · "
                    + "SHA-256 " + impressaoDigital(certificado));
            definirEscritaAtiva(sessao.ativa());
            campoTexto.requestFocusInWindow();
        }, erro -> {
            cabecalho.setForeground(VERMELHO);
            cabecalho.setText(nome + ": " + descrever(erro));
        });
    }

    private void enviar() {
        String destinatario = listaContactos.getSelectedValue();
        String texto = campoTexto.getText();

        if (destinatario == null || texto.isBlank()) {
            return;
        }

        definirEscritaAtiva(false);

        emFundo(() -> sessao.enviar(destinatario, texto), resposta -> {
            campoTexto.setText("");
            acrescentar(destinatario, "eu", texto
                    + (resposta.startsWith("Destinatário desligado")
                            ? "   [guardada no relay]" : ""));
            evento(resposta);
            definirEscritaAtiva(sessao.ativa());
            campoTexto.requestFocusInWindow();
        }, erro -> {
            evento("Envio recusado: " + descrever(erro));
            definirEscritaAtiva(sessao.ativa());
        });
    }

    private void levantar() {
        emFundo(() -> sessao.levantar(), this::evento,
                erro -> evento("Levantamento recusado: " + descrever(erro)));
    }

    private void sair() {
        SessaoCliente aberta = sessao;
        if (aberta != null) {
            aberta.close();
        }
        janela.dispose();
        System.exit(0);
    }

    // ------------------------------------------------------------------
    // Ouvinte: chamado pelas threads da sessão, não pela da interface.
    // ------------------------------------------------------------------

    @Override
    public void mensagemVerificada(String remetente, String texto) {
        SwingUtilities.invokeLater(() -> {
            // Só chegamos aqui com a assinatura verificada: o remetente
            // é mesmo quem diz ser, por isso pode entrar nos contactos.
            juntarContacto(remetente);
            acrescentar(remetente, remetente, texto);
            evento("Mensagem de " + remetente
                    + ": assinatura verificada e conteúdo decifrado.");
        });
    }

    @Override
    public void mensagemRejeitada(String motivo) {
        // O remetente indicado não é fiável: não a pomos em nenhuma conversa.
        SwingUtilities.invokeLater(() -> {
            evento("MENSAGEM REJEITADA: " + motivo);
            mostrarEstado("Foi rejeitada uma mensagem que não passou "
                    + "a verificação. Ver eventos.", VERMELHO);
            janela.getToolkit().beep();
        });
    }

    @Override
    public void ligacaoTerminada(String motivo) {
        SwingUtilities.invokeLater(() -> {
            evento("Ligação terminada: " + motivo);
            mostrarEstado("Desligado do relay. Reinicia o cliente.", VERMELHO);
            definirEscritaAtiva(false);
            botaoLevantar.setEnabled(false);
        });
    }

    // ------------------------------------------------------------------
    // Auxiliares
    // ------------------------------------------------------------------

    /** Corre um pedido fora da interface e volta a ela com o resultado. */
    private <T> void emFundo(Callable<T> pedido, Consumer<T> sucesso,
            Consumer<Exception> falha) {
        fundo.submit(() -> {
            try {
                T resultado = pedido.call();
                SwingUtilities.invokeLater(() -> sucesso.accept(resultado));
            } catch (Exception erro) {
                SwingUtilities.invokeLater(() -> falha.accept(erro));
            }
        });
    }

    private void acrescentar(String contacto, String autor, String texto) {
        StringBuilder historico =
                conversas.computeIfAbsent(contacto, k -> new StringBuilder());
        String linha = "[" + LocalTime.now().format(HORA) + "] "
                + autor + ": " + texto + "\n";
        historico.append(linha);

        if (contacto.equals(listaContactos.getSelectedValue())) {
            conversa.append(linha);
            conversa.setCaretPosition(conversa.getDocument().getLength());
        } else {
            porLer.add(contacto);
            listaContactos.repaint();
        }
    }

    private void evento(String texto) {
        eventos.append("[" + LocalTime.now().format(HORA) + "] "
                + texto + "\n");
        eventos.setCaretPosition(eventos.getDocument().getLength());
    }

    private void mostrarEstado(String texto, Color cor) {
        estado.setForeground(cor);
        estado.setText(texto);
    }

    private void definirEscritaAtiva(boolean ativa) {
        campoTexto.setEnabled(ativa);
        botaoEnviar.setEnabled(ativa);
    }

    private static String impressaoDigital(X509Certificate certificado)
            throws RuntimeException {
        try {
            byte[] resumo = MessageDigest.getInstance("SHA-256")
                    .digest(certificado.getEncoded());
            // Os primeiros 8 bytes chegam para comparar de viva voz.
            return HexFormat.ofDelimiter(":").withUpperCase()
                    .formatHex(resumo, 0, 8) + "…";
        } catch (Exception erro) {
            throw new IllegalStateException(erro);
        }
    }

    private static String descrever(Exception erro) {
        String mensagem = erro.getMessage();
        if (mensagem == null || mensagem.isBlank()) {
            return erro.getClass().getSimpleName();
        }
        if (erro instanceof ConfiguracaoTLS.PalavraPasseIncorreta) {
            return "Palavra-passe incorreta.";
        }
        if (erro instanceof java.net.ConnectException) {
            return "Não foi possível ligar ao relay em localhost:8443.";
        }
        return mensagem;
    }

    /** Texto vindo da rede nunca é interpretado como HTML. */
    private static JLabel semHtml(JLabel rotulo) {
        rotulo.putClientProperty("html.disable", Boolean.TRUE);
        return rotulo;
    }

    private static JTextArea areaTexto() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    /** Assinala a negrito os contactos com mensagens por ler. */
    private final class RenderizadorContacto extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> lista,
                Object valor, int indice, boolean selecionado, boolean foco) {
            JLabel rotulo = (JLabel) super.getListCellRendererComponent(
                    lista, valor, indice, selecionado, foco);
            rotulo.putClientProperty("html.disable", Boolean.TRUE);
            if (porLer.contains(valor)) {
                rotulo.setText("● " + valor);
                rotulo.setFont(rotulo.getFont().deriveFont(Font.BOLD));
            }
            return rotulo;
        }
    }
}
