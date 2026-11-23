#!/usr/bin/env bash
# Arranca a Autoridade (em fundo) e o relay. Ctrl+C para os dois.
# No primeiro arranque, a Autoridade cria a CA e as identidades dos
# servidores; nos seguintes não é pedido nada.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -d out ] || bash scripts/compilar.sh

java -cp out pt.ua.estga.mensageiro.autoridade.Autoridade &
AUTORIDADE=$!
trap 'kill "$AUTORIDADE" 2>/dev/null || true' EXIT

# O relay precisa da identidade que a Autoridade cria no primeiro arranque.
for _ in $(seq 1 120); do
  [ -f certificados/publicos/relay.crt ] && break
  kill -0 "$AUTORIDADE" 2>/dev/null || { echo 'A Autoridade terminou com erro.'; exit 1; }
  sleep 0.5
done

java -cp out pt.ua.estga.mensageiro.relay.Relay
