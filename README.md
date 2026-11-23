# Mensageiro Seguro

**Segurança Informática · UA / ESTGA · 2026–27 · Grupo 9**

Aplicação de mensagens em Java que permite trocar mensagens cifradas e assinadas através de um servidor de encaminhamento (*relay*). O relay conhece os dados necessários ao encaminhamento, mas não possui as chaves privadas dos clientes para recuperar o conteúdo.

Desenvolvido por **João Pedro Soares de Oliveira** e **Cristiano Norberto Pereira Dias Miguel Saraiva**, na unidade curricular de Segurança Informática, lecionada por **Hélder Gomes**.

O contexto atribuído ao grupo é uma organização humanitária com ligações intermitentes à rede: por isso o relay guarda as mensagens para destinatários desligados até estes as levantarem.

## Como funciona

1. O cliente e o relay autenticam-se mutuamente através de certificados, numa ligação TLS 1.3.
2. O relay associa o registo à identidade do certificado apresentado.
3. O remetente procura o destinatário e valida o respetivo certificado.
4. O cliente cifra a mensagem com uma chave AES nova, protege essa chave para o destinatário e assina o envelope.
5. O relay encaminha o envelope para o destinatário ligado ou guarda-o até este o levantar.
6. O destinatário valida o certificado do remetente, verifica a assinatura e recupera o conteúdo.

**TLS protege cada ligação ao relay. O envelope protege o conteúdo de cliente a cliente, incluindo perante o próprio relay.**

## Módulos do grupo

| Módulo | Requisito | Estado na entrega 2 |
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
| Certificados | X.509; CA do grupo; ficheiros PKCS12 |
| Chaves de identidade | RSA de 3072 bits |
| Cifra do conteúdo | AES-256-GCM; nonce de 96 bits; etiqueta de 128 bits |
| Proteção da chave AES | RSA-OAEP com SHA-256 e MGF1 SHA-256 |
| Assinatura do envelope | `SHA256withRSA`, após a cifra |
| Auditoria | SHA-256 encadeado; pontos de controlo `SHA256withRSA` do relay |
| Protocolo | Binário próprio, com comprimentos explícitos |

A assinatura abrange os bytes exatos do corpo do envelope, incluindo metadados, chave protegida, nonce e cifra. A verificação precede a decifra. Não é utilizada serialização nativa de objetos Java.

## Começar

### Requisitos

- JDK 21, com `java`, `javac` e `keytool` disponíveis no Terminal.
- Bash para os scripts de preparação e compilação.
- Três Terminais interativos para o relay e os dois clientes.
- OpenSSL apenas se quiseres repetir os testes TLS negativos descritos na documentação.

A demonstração atual corre **no mesmo computador**, através de `localhost:8443`.

### 1. Obter o projeto

```bash
git clone git@github.com:cristiianoo/MensageiroSeguro.git
cd MensageiroSeguro
git switch entrega-2
```

Para usar exatamente a revisão marcada como primeira entrega:

```bash
git switch --detach entrega-1-2026-11-09
```

A etiqueta identifica um commit fixo; o ramo pode receber correções posteriores. Para desenvolver, usa um ramo, não o estado destacado da etiqueta.

### 2. Gerar certificados e compilar

Na raiz do projeto:

```bash
bash scripts/gerar-certificados.sh
bash scripts/compilar.sh
bash scripts/testar-envelope.sh
bash scripts/testar-certificados.sh
```

O primeiro script pede uma palavra-passe e cria novas identidades locais. Nesta preparação de demonstração, todos os PKCS12 usam essa palavra-passe. O script não substitui uma pasta `certificados` existente.

**Os certificados só precisam de ser gerados uma vez por preparação.** Não repetir este passo a cada arranque.

A preparação centralizada serve para demonstrar o sistema num computador. Num cenário de utilização, cada titular conserva a sua chave privada e a CA é mantida separada do relay.

### 3. Arrancar o relay

No primeiro Terminal:

```bash
java -cp out pt.ua.estga.mensageiro.relay.Relay
```

Introduzir as palavras-passe da identidade e da confiança. Na preparação feita pelo script, são a mesma palavra-passe escolhida anteriormente.

### 4. Arrancar os clientes

No segundo Terminal, na raiz do projeto:

```bash
java -cp out pt.ua.estga.mensageiro.cliente.Cliente cristiano
```

No terceiro Terminal:

```bash
java -cp out pt.ua.estga.mensageiro.cliente.Cliente joao
```

Esperar que ambos apresentem `Registo confirmado`.

### 5. Trocar mensagens

No João:

```text
procurar cristiano
enviar cristiano
```

Escrever o texto quando aparecer `Mensagem:`. No Cristiano deverá aparecer:

```text
Mensagem verificada de joao: Olá, Cristiano!
```

Responder no Cristiano com `enviar joao`.

| Comando | Função |
|---|---|
| `procurar <nome>` | Obter e validar o certificado de um utilizador |
| `enviar <nome>` | Criar e enviar um envelope protegido |
| `levantar` | Receber as mensagens guardadas no relay |
| `sair` | Terminar o cliente |

Parar o relay com `Ctrl+C`; é escrito um último ponto de controlo na auditoria. O diretório, as mensagens pendentes e o registo ficam em `dados-relay/` e sobrevivem a reinícios.

### 6. Mensagens para quem está desligado

Com o Cristiano desligado, no João: `enviar cristiano`. O relay responde `Destinatário desligado: envelope guardado no relay.` Quando o Cristiano voltar a ligar, as mensagens são levantadas automaticamente (ou com o comando `levantar`). O pedido não leva nome: o relay entrega apenas a caixa do certificado da sessão TLS.

### 7. Verificar a auditoria

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
| `src/pt/ua/estga/mensageiro/cliente/` | Cliente interativo e receção de mensagens |
| `src/pt/ua/estga/mensageiro/relay/` | Registo, descoberta, encaminhamento, armazenamento diferido e auditoria |
| `src/pt/ua/estga/mensageiro/auditoria/` | Verificador independente do registo de auditoria |
| `src/pt/ua/estga/mensageiro/seguranca/` | TLS, identidades, validação de certificados, envelope e testes |
| `src/pt/ua/estga/mensageiro/protocolo/` | Leitura e escrita das tramas |
| `scripts/` | Preparação dos certificados, compilação e testes |
| `dados-relay/` | Criado pelo relay: caixas, diretório e auditoria (fora do git) |
| `docs/` | Documento de arquitetura e relatório de ameaças |
| `evidencias/` | Resultados de testes guardados |

## Verificação

| Script | O que verifica |
|---|---|
| `testar-envelope.sh` | Recuperação; assinatura, cifra e metadados alterados; chave privada errada; corpo reassinado por terceiro; reencaminhamento para outro destinatário |
| `testar-certificados.sh` | Rejeição de certificado de outro utilizador, do relay, da CA e adulterado |
| `testar-auditoria.sh` | Registo íntegro aceite; entradas alteradas, removidas e reordenadas rejeitadas |

Demonstrados manualmente: rejeição de cliente sem certificado, de relay autoassinado e de servidor com certificado da CA emitido para cliente; armazenamento e levantamento depois de reiniciar o relay; um utilizador não levanta as mensagens de outro. Resultados em `evidencias/` e no relatório de ameaças.

## Limitações atuais

- Sem controlo de repetição de envelopes, revogação ou renovação automática de certificados.
- O levantamento apaga cada mensagem depois de a escrever na ligação, sem confirmação do cliente.
- O administrador do relay pode truncar o registo de auditoria depois do último ponto de controlo, ou reescrevê-lo com a chave do relay; só um ponto de controlo guardado fora do relay o deteta.
- O registo de auditoria guarda o par remetente/destinatário de cada envio.
- Sem sigilo futuro do envelope RSA.
- O relay observa metadados e pode atrasar, descartar ou repetir envelopes.
- Limites por trama e por caixa (200 mensagens), mas sem proteção completa contra negação de serviço.
- Cliente de demonstração limitado às identidades `joao` e `cristiano`, em `localhost`.

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