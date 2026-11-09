# Mensageiro Seguro

**Segurança Informática · UA / ESTGA · 2026–27 · Grupo 9**

Aplicação de mensagens em Java que permite trocar mensagens cifradas e assinadas através de um servidor de encaminhamento (*relay*). O relay conhece os dados necessários ao encaminhamento, mas não possui as chaves privadas dos clientes para recuperar o conteúdo.

Desenvolvido por **João Pedro Soares de Oliveira** e **Cristiano Norberto Pereira Dias Miguel Saraiva**, na unidade curricular de Segurança Informática, lecionada por **Hélder Gomes**.

O contexto atribuído ao grupo é uma organização humanitária com ligações intermitentes à rede. Esse contexto enquadra o trabalho; o armazenamento offline será acrescentado numa fase seguinte.

## Como funciona

1. O cliente e o relay autenticam-se mutuamente através de certificados, numa ligação TLS 1.3.
2. O relay associa o registo à identidade do certificado apresentado.
3. O remetente procura o destinatário e valida o respetivo certificado.
4. O cliente cifra a mensagem com uma chave AES nova, protege essa chave para o destinatário e assina o envelope.
5. O relay encaminha o envelope para o destinatário ligado.
6. O destinatário valida o certificado do remetente, verifica a assinatura e recupera o conteúdo.

**TLS protege cada ligação ao relay. O envelope protege o conteúdo de cliente a cliente, incluindo perante o próprio relay.**

## Módulos do grupo

| Módulo | Requisito | Estado na entrega 1 |
|---|---|---|
| A — Identidade e confiança | TLS com autenticação mútua e certificados | Implementado no fluxo de demonstração |
| B — Proteção das mensagens | Envelope híbrido com assinatura | Implementado e testado |
| C — Auditoria do relay | Hashes encadeados, pontos de controlo assinados e verificador independente | Planeado; ainda não implementado |

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
git switch entrega-1
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
| `sair` | Terminar o cliente |

Parar o relay com `Ctrl+C`. Reiniciar o relay apaga os registos em memória: voltar a ligar os clientes para os registar.

> `Envelope encaminhado` confirma escrita na ligação do destinatário. Não constitui confirmação de aceitação ou leitura da mensagem.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `src/pt/ua/estga/mensageiro/cliente/` | Cliente interativo e receção de mensagens |
| `src/pt/ua/estga/mensageiro/relay/` | Registo, descoberta e encaminhamento online |
| `src/pt/ua/estga/mensageiro/seguranca/` | TLS, identidades, validação de certificados, envelope e testes |
| `src/pt/ua/estga/mensageiro/protocolo/` | Leitura e escrita das tramas |
| `scripts/` | Preparação dos certificados, compilação e teste do envelope |
| `docs/` | Documento de arquitetura e relatório de ameaças |
| `evidencias/` | Resultados de testes guardados |

## Verificação

O `TesteEnvelope` verifica cinco casos:

- Recuperação correta da mensagem original.
- Rejeição de assinatura adulterada.
- Rejeição de conteúdo cifrado adulterado.
- Rejeição de metadados adulterados.
- Falha de abertura com uma chave privada diferente.

Durante o desenvolvimento foram também demonstrados o envio online nos dois sentidos, a rejeição de cliente sem certificado e a rejeição de um servidor com certificado não confiável.

A verificação de cada nova revisão deve incluir a execução numa preparação nova, a procura de um utilizador inexistente e o envio para um destinatário desligado. Os resultados detalhados e os casos ainda pendentes constam do `README` do pacote de entrega e do relatório de ameaças.

## Limitações atuais

- Envio apenas online; sem armazenamento diferido nem levantamento de mensagens.
- Diretório de utilizadores em memória; perde-se ao reiniciar o relay.
- Cliente de demonstração limitado às identidades `joao` e `cristiano`.
- Auditoria do módulo C ainda não implementada.
- Sem controlo de repetição de envelopes, revogação ou renovação automática de certificados.
- Sem sigilo futuro do envelope RSA: o compromisso posterior da chave privada pode expor envelopes anteriormente recolhidos.
- O relay observa metadados e pode atrasar, descartar ou repetir envelopes.
- Existem limites de tamanho e de fila no cliente, mas não proteção completa contra negação de serviço.
- A segurança pressupõe a integridade da CA, dos clientes e da configuração local de confiança.

As limitações e riscos residuais são parte da análise do trabalho e serão revistos nas fases seguintes.

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

Foi utilizado ChatGPT para apoiar explicações, planeamento, propostas de código, revisão e documentação. Os resultados têm de ser revistos e validados pelos elementos do grupo. A declaração formal de utilização de IA será completada no relatório final, conforme o modelo do docente.
