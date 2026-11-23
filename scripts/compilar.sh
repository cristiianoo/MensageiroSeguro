#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p out
javac -encoding UTF-8 -d out \
 src/pt/ua/estga/mensageiro/seguranca/*.java \
 src/pt/ua/estga/mensageiro/protocolo/*.java \
 src/pt/ua/estga/mensageiro/relay/*.java \
 src/pt/ua/estga/mensageiro/cliente/*.java \
 src/pt/ua/estga/mensageiro/auditoria/*.java
echo 'Compilação concluída.'
