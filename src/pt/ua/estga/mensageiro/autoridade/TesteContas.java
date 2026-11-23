package pt.ua.estga.mensageiro.autoridade;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Testa as regras de criação de conta que a Autoridade aplica,
 * sem rede: o pedido é criado e validado em memória.
 */
public final class TesteContas {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
        gerador.initialize(3072);
        KeyPair maria = gerador.generateKeyPair();
        KeyPair intruso = gerador.generateKeyPair();

        PedidoConta valido = PedidoConta.criar("maria", maria);
        PedidoConta.descodificar(valido.codificar()).validar();
        System.out.println("OK — pedido válido aceite.");

        // Chave pública da maria, mas assinado por outra chave: quem pede
        // não prova que tem a chave privada que quer certificar.
        PedidoConta comIntruso = PedidoConta.criar("maria", intruso);
        rejeitar(new PedidoConta("maria", valido.chavePublica(),
                        comIntruso.assinatura()),
                "prova de posse com outra chave rejeitada");

        // Pedido válido para "maria" com o nome trocado no caminho.
        rejeitar(new PedidoConta("mario", valido.chavePublica(),
                        valido.assinatura()),
                "nome alterado depois de assinado rejeitado");

        KeyPairGenerator fraco = KeyPairGenerator.getInstance("RSA");
        fraco.initialize(2048);
        rejeitar(PedidoConta.criar("curta", fraco.generateKeyPair()),
                "chave de 2048 bits rejeitada");

        rejeitar(new PedidoConta("relay", valido.chavePublica(),
                        valido.assinatura()),
                "nome reservado rejeitado");

        rejeitar(new PedidoConta("Maria Silva", valido.chavePublica(),
                        valido.assinatura()),
                "nome com caracteres inválidos rejeitado");

        byte[] adulterado = valido.codificar();
        adulterado[adulterado.length - 1] ^= 1;
        rejeitar(PedidoConta.descodificar(adulterado),
                "assinatura adulterada rejeitada");
    }

    private static void rejeitar(PedidoConta pedido, String caso) {
        try {
            pedido.validar();
        } catch (Exception esperado) {
            System.out.println("OK — " + caso + ".");
            return;
        }
        throw new AssertionError("Aceite indevidamente: " + caso);
    }

}
