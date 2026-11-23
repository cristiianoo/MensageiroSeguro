# Mensageiro Seguro

**Segurança Informática · UA / ESTGA · 2026–27 · Grupo 9**

Aplicação de mensagens em Java que permite trocar mensagens cifradas e assinadas através de um servidor de encaminhamento (*relay*). O relay conhece os dados necessários ao encaminhamento, mas não possui as chaves privadas dos clientes para recuperar o conteúdo.

Desenvolvido por **João Pedro Soares de Oliveira** e **Cristiano Norberto Pereira Dias Miguel Saraiva**, na unidade curricular de Segurança Informática, lecionada por **Hélder Gomes**.

O contexto atribuído ao grupo é uma organização humanitária com ligações intermitentes à rede: por isso o relay guarda as mensagens para destinatários desligados até estes as levantarem.

## Como funciona

1. Para criar conta, o cliente gera o seu par de chaves e pede um certificado à Autoridade, provando que tem a chave privada. A chave privada nunca sai do computador do utilizador.
2. O cliente e o relay autenticam-se mutuamente através de certificados, numa ligação TLS 1.3. O relay associa o registo à identidade do certificado apresentado.
3. O remetente procura o destinatário e valida o respetivo certificado.
4. O cliente cifra a mensagem com uma chave AES nova, protege essa chave para o destinatário e assina o envelope.
5. O relay encaminha o envelope para o destinatário ligado ou guarda-o até este o levantar.
6. O destinatário valida o certificado do remetente, verifica a assinatura e recupera o conteúdo.

**TLS protege cada ligação ao relay. O envelope protege o conteúdo de cliente a cliente, incluindo perante o próprio relay.**

## Módulos do grupo

| Módulo | Requisito | Estado |
|---|---|---|
| A — Identidade e confiança | TLS com autenticação mútua e certificados | Implementado; rejeições demonstradas |
| B — Proteção das mensagens | Envelope híbrido com assinatura | Implementado; 7 casos em `TesteEnvelope` |
| C — Auditoria do relay | Hashes encadeados, pontos de controlo assinados e verificador independente | Implementado; `testar-auditoria.sh` |

## Tecnologias e mecanismos

| Elemento | Escolha atual |
|---|---|
| Linguagem | Java 21 |
| Dependências da implementação | Apenas bibliotecas do JDK |
| Comunicação | `SSLSocket` / `SSLServerSocket`, sobre TCP |
| Transporte | TLS 1.3 com autenticação mútua |
| Certificados | X.509 v3 emitidos pela Autoridade do grupo (gerador DER próprio, só API pública do JDK) |
| Contas | PKCS12 cifrado com a palavra-passe pessoal (PBKDF2, 600 000 iterações) |
| Chaves de identidade | RSA de 3072 bits |
| Cifra do conteúdo | AES-256-GCM; nonce de 96 bits; etiqueta de 128 bits |
| Proteção da chave AES | RSA-OAEP com SHA-256 e MGF1 SHA-256 |
| Assinatura do envelope | `SHA256withRSA`, após a cifra |
| Auditoria | SHA-256 encadeado; pontos de controlo `SHA256withRSA` do relay |
| Protocolo | Binário próprio, com comprimentos explícitos |

A assinatura abrange os bytes exatos do corpo do envelope, incluindo metadados, chave protegida, nonce e cifra. A verificação precede a decifra. Não é utilizada serialização nativa de objetos Java.

## Começar

### Requisitos

- JDK 21, com `java` e `javac` disponíveis no Terminal.
- Bash para os scripts.
- Um Terminal para os servidores e um por cliente.

A demonstração corre **no mesmo computador**: relay em `localhost:8443`, Autoridade em `localhost:8444`.

### 1. Obter o projeto

```bash
git clone git@github.com:cristiianoo/MensageiroSeguro.git
cd MensageiroSeguro
bash scripts/compilar.sh
```

As revisões entregues estão marcadas com etiquetas (por exemplo `git switch --detach entrega-1-2026-11-09`).

### 2. Arrancar os servidores

```bash
bash scripts/arrancar-servidores.sh
```

Arranca a **Autoridade** (em fundo) e o **relay**. No primeiro arranque, a Autoridade cria a CA do grupo e as identidades dos dois servidores; os segredos ficam em ficheiros só legíveis pelo dono (permissões 600, fora do git). Não é pedida nenhuma palavra-passe. `Ctrl+C` para os dois; o relay escreve um último ponto de controlo na auditoria.

> Uma pasta `certificados` criada pelo antigo `gerar-certificados.sh` não é aproveitada: movê-la (`mv certificados certificados-antigos`) e arrancar de novo.

### 3. Criar conta e entrar

Numa janela:

```bash
java -cp out pt.ua.estga.mensageiro.cliente.ClienteGUI
```

Ou na consola:

```bash
java -cp out pt.ua.estga.mensageiro.cliente.Cliente
```

Na primeira vez, escolher um nome (3 a 32 caracteres: minúsculas, algarismos, `_` ou `-`) e uma palavra-passe pessoal (mínimo 8 caracteres), marcando **Criar conta nova** (na consola, responder `s`). O cliente:

1. gera um par de chaves RSA de 3072 bits neste computador;
2. envia à Autoridade o nome e a chave pública, assinados com a chave privada (prova de posse);
3. confirma que o certificado recebido é da CA, para este nome e para esta chave;
4. guarda a chave e o certificado em `certificados/contas/<nome>.p12`, cifrado com a palavra-passe.

Nas vezes seguintes, basta o nome e a palavra-passe. **A palavra-passe não é enviada a ninguém**: só decifra o ficheiro da conta neste computador. Cada nome pertence a quem o pedir primeiro.

### 4. Trocar mensagens

Na janela, **+ Contacto** acrescenta alguém pelo nome (o certificado é pedido ao relay e validado com a CA). O cabeçalho mostra a impressão digital SHA-256 do certificado, para comparar com o contacto por outro meio. O painel «Eventos de segurança» mostra a ligação TLS, as mensagens levantadas e as rejeitadas.

Na consola:

| Comando | Função |
|---|---|
| `procurar <nome>` | Obter e validar o certificado de um utilizador |
| `enviar <nome>` | Criar e enviar um envelope protegido |
| `levantar` | Receber as mensagens guardadas no relay |
| `sair` | Terminar o cliente |

A consola e a janela usam a mesma `SessaoCliente` e podem falar uma com a outra.

### 5. Mensagens para quem está desligado

Se o destinatário estiver desligado, o relay responde `Destinatário desligado: envelope guardado no relay.` Quando ele voltar a entrar, as mensagens são levantadas automaticamente (ou com `levantar`). O pedido não leva nome: o relay entrega apenas a caixa do certificado da sessão TLS. O diretório, as mensagens pendentes e o registo ficam em `dados-relay/` e sobrevivem a reinícios.

### 6. Verificar a auditoria

```bash
bash scripts/testar-auditoria.sh
```

Verifica o registo real e três cópias adulteradas (entrada alterada, removida e reordenada). O verificador pode ser usado diretamente:

```bash
java -cp out pt.ua.estga.mensageiro.auditoria.VerificadorAuditoria \
  dados-relay/auditoria.log certificados/publicos/relay.crt certificados/publicos/ca-grupo09.crt
```

> `Envelope encaminhado` confirma escrita na ligação do destinatário. Não constitui confirmação de aceitação ou leitura da mensagem.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `src/pt/ua/estga/mensageiro/autoridade/` | Autoridade de registo (única com a chave da CA) e pedidos de conta |
| `src/pt/ua/estga/mensageiro/cliente/` | Contas, sessão com o relay (`SessaoCliente`), cliente de consola e interface gráfica Swing |
| `src/pt/ua/estga/mensageiro/relay/` | Registo, descoberta, encaminhamento, armazenamento diferido e auditoria |
| `src/pt/ua/estga/mensageiro/auditoria/` | Verificador independente do registo de auditoria |
| `src/pt/ua/estga/mensageiro/seguranca/` | TLS, emissão e validação de certificados, armazenamento de chaves, envelope e testes |
| `src/pt/ua/estga/mensageiro/protocolo/` | Leitura e escrita das tramas |
| `scripts/` | Compilação, arranque dos servidores e testes |
| `certificados/` | Criado pela Autoridade e pelos clientes: CA, servidores, contas (fora do git) |
| `dados-relay/` | Criado pelo relay: caixas, diretório e auditoria (fora do git) |
| `docs/` | Documento de arquitetura e relatório de ameaças (versões da entrega 1, 2 e final) |
| `evidencias/` | Resultados de testes guardados |

## Verificação

| Script | O que verifica |
|---|---|
| `testar-envelope.sh` | Recuperação; assinatura, cifra e metadados alterados; chave privada errada; corpo reassinado por terceiro; reencaminhamento para outro destinatário |
| `testar-certificados.sh` | Rejeição de certificado de outro utilizador, do relay, da CA, de outra CA e adulterado |
| `testar-contas.sh` | Pedido de conta válido aceite; prova de posse com outra chave, nome alterado, chave de 2048 bits, nome reservado ou inválido e assinatura adulterada rejeitados |
| `testar-auditoria.sh` | Registo íntegro aceite; entradas alteradas, removidas e reordenadas rejeitadas |

O teste de integração das contas (servidores, criação de contas, mensagem guardada, erros) está em `evidencias/teste-integracao-contas.txt`.

Demonstrados manualmente: rejeição de cliente sem certificado, de relay autoassinado e de servidor com certificado da CA emitido para cliente; armazenamento e levantamento depois de reiniciar o relay; um utilizador não levanta as mensagens de outro. Resultados em `evidencias/` e no relatório de ameaças.

## Limitações atuais

- Sem controlo de repetição de envelopes, revogação ou renovação automática de certificados.
- A criação de conta não confirma a identidade de quem a pede: cada nome fica para quem o pedir primeiro.
- Quem esquecer a palavra-passe perde a conta (a chave privada só existe cifrada com ela) e o nome continua ocupado.
- Os segredos dos servidores estão em ficheiros só legíveis pelo dono: quem tiver acesso ao disco do servidor tem as chaves. A Autoridade e o relay correm no mesmo computador nesta demonstração.
- O histórico das conversas não é guardado entre sessões.
- O levantamento apaga cada mensagem depois de a escrever na ligação, sem confirmação do cliente.
- O administrador do relay pode truncar o registo de auditoria depois do último ponto de controlo, ou reescrevê-lo com a chave do relay; só um ponto de controlo guardado fora do relay o deteta.
- O registo de auditoria guarda o par remetente/destinatário de cada envio.
- Sem sigilo futuro do envelope RSA.
- O relay observa metadados e pode atrasar, descartar ou repetir envelopes.
- Limites por trama e por caixa (200 mensagens), mas sem proteção completa contra negação de serviço.
- Demonstração em `localhost`.

## Entregas

| Data | Objetivo |
|---|---|
| 09/11/2026 | Primeira troca protegida, arquitetura inicial e análise inicial de ameaças |
| 30/11/2026 | Sistema completo, armazenamento diferido, autorização e módulos A/B/C |
| 14/12/2026 | Versão final, testes e documentação |
| 21/12/2026 | Defesa individual |

## Cuidados com o repositório

Não adicionar chaves privadas, palavras-passe, ficheiros PKCS12 ou certificados gerados para a demonstração. Esses ficheiros são criados localmente pelo script. Manter as exclusões adequadas no `.gitignore`.

## Utilização de IA

Foram utilizados ChatGPT e Claude (Claude Code) para apoiar explicações, planeamento, propostas de código, testes, revisão e documentação. Os resultados têm de ser revistos e validados pelos elementos do grupo. A declaração formal de utilização de IA será completada no relatório final, conforme o modelo do docente.