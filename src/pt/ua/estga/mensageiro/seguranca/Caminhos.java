package pt.ua.estga.mensageiro.seguranca;

import java.nio.file.Path;

/**
 * Onde cada coisa fica. Tudo está fora do git (.gitignore).
 *
 * Numa instalação real, ca/ e autoridade/ estariam na máquina da
 * Autoridade, relay/ na do relay e contas/ no computador de cada
 * utilizador. Na demonstração está tudo na mesma pasta.
 */
public final class Caminhos {

    public static final Path RAIZ = Path.of("certificados");

    /** Públicos: podem ser distribuídos com o programa. */
    public static final Path CA_PUBLICO =
            RAIZ.resolve("publicos/ca-grupo09.crt");
    public static final Path RELAY_PUBLICO =
            RAIZ.resolve("publicos/relay.crt");

    /** Só a Autoridade lê estes ficheiros. */
    public static final Path CA = RAIZ.resolve("ca/ca-grupo09.p12");
    public static final Path CA_SEGREDO = RAIZ.resolve("ca/ca.segredo");
    public static final Path AUTORIDADE =
            RAIZ.resolve("autoridade/autoridade.p12");
    public static final Path AUTORIDADE_SEGREDO =
            RAIZ.resolve("autoridade/autoridade.segredo");
    public static final Path EMITIDOS = RAIZ.resolve("autoridade/emitidos");

    /** Só o relay lê estes ficheiros. */
    public static final Path RELAY = RAIZ.resolve("relay/relay.p12");
    public static final Path RELAY_SEGREDO =
            RAIZ.resolve("relay/relay.segredo");

    /** Contas dos utilizadores neste computador. */
    public static final Path CONTAS = RAIZ.resolve("contas");

    public static final int PORTA_RELAY = 8443;
    public static final int PORTA_AUTORIDADE = 8444;

    private Caminhos() {
    }

    public static Path conta(String nome) {
        return CONTAS.resolve(nome + ".p12");
    }

    public static Path contactos(String nome) {
        return CONTAS.resolve(nome + ".contactos");
    }
}
