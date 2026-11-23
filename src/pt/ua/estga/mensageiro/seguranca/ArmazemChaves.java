package pt.ua.estga.mensageiro.seguranca;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

/** Guarda identidades em PKCS12 e segredos dos servidores em disco. */
public final class ArmazemChaves {

    /**
     * Iterações do PBKDF2 que protege o PKCS12. O valor por omissão do
     * JDK (10 000) torna barato testar palavras-passe se o ficheiro
     * for roubado; com 600 000 cada tentativa custa 60 vezes mais.
     */
    private static final String ITERACOES = "600000";

    private static final SecureRandom ALEATORIO = new SecureRandom();

    private ArmazemChaves() {
    }

    /**
     * Cria um PKCS12 com a chave privada e a cadeia de certificados.
     * Falha se o ficheiro já existir: nunca substituímos uma identidade.
     */
    public static void guardarIdentidade(
            Path ficheiro,
            String alias,
            PrivateKey chave,
            char[] palavraPasse,
            X509Certificate... cadeia) throws Exception {

        if (Files.exists(ficheiro)) {
            throw new FileAlreadyExistsException(ficheiro.toString());
        }

        // Lidas pelo JDK ao guardar um PKCS12 novo.
        Security.setProperty("keystore.pkcs12.keyPbeIterationCount", ITERACOES);
        Security.setProperty("keystore.pkcs12.macIterationCount", ITERACOES);

        KeyStore armazem = KeyStore.getInstance("PKCS12");
        armazem.load(null, null);
        armazem.setKeyEntry(alias, chave, palavraPasse, (Certificate[]) cadeia);

        criarDiretorio(ficheiro.getParent());

        // Escrevemos num temporário só legível pelo dono e só depois
        // lhe damos o nome final: não fica um PKCS12 meio escrito.
        Path nomeTemporario =
                ficheiro.resolveSibling(ficheiro.getFileName() + ".tmp");
        Files.deleteIfExists(nomeTemporario);   // de uma tentativa falhada
        Path temporario = criarPrivado(nomeTemporario);

        try (OutputStream saida = Files.newOutputStream(temporario)) {
            armazem.store(saida, palavraPasse);
        }

        Files.move(temporario, ficheiro, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Segredo aleatório de um servidor (CA, Autoridade, relay), usado
     * como palavra-passe do seu PKCS12 para arrancar sem perguntar nada.
     * Fica num ficheiro só legível pelo dono (permissões 600).
     */
    public static char[] criarSegredo(Path ficheiro) throws IOException {
        byte[] bytes = new byte[32];
        ALEATORIO.nextBytes(bytes);
        String segredo = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bytes);

        criarDiretorio(ficheiro.getParent());
        Path criado = criarPrivado(ficheiro);
        Files.writeString(criado, segredo, StandardCharsets.US_ASCII);
        return segredo.toCharArray();
    }

    public static char[] lerSegredo(Path ficheiro) throws IOException {
        return Files.readString(ficheiro, StandardCharsets.US_ASCII)
                .strip().toCharArray();
    }

    public static void escreverPublico(Path ficheiro, String texto)
            throws IOException {
        criarDiretorio(ficheiro.getParent());
        Files.writeString(ficheiro, texto, StandardCharsets.US_ASCII);
    }

    /** Diretório só acessível ao dono (700), quando o sistema o permite. */
    private static void criarDiretorio(Path diretorio) throws IOException {
        if (Files.isDirectory(diretorio)) {
            return;
        }
        try {
            Files.createDirectories(diretorio,
                    PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rwx------")));
        } catch (UnsupportedOperationException semPosix) {
            Files.createDirectories(diretorio);   // Windows
        }
    }

    /** Ficheiro novo com permissões 600 desde a criação (sem janela). */
    private static Path criarPrivado(Path ficheiro) throws IOException {
        try {
            return Files.createFile(ficheiro,
                    PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException semPosix) {
            return Files.createFile(ficheiro);   // Windows
        }
    }
}
