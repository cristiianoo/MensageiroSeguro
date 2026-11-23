#!/usr/bin/env bash
# Módulo C: verifica o registo real e três cópias adulteradas.
# O registo original nunca é alterado.
set -uo pipefail
cd "$(dirname "$0")/.."

REGISTO=dados-relay/auditoria.log
CERT_RELAY=certificados/publicos/relay.crt
CA=certificados/publicos/ca-grupo09.crt
VERIFICAR=(java -cp out pt.ua.estga.mensageiro.auditoria.VerificadorAuditoria)

[ -f "$REGISTO" ] || { echo "Não existe $REGISTO. Corre o relay e troca algumas mensagens primeiro."; exit 1; }

ENTRADAS=$(grep -c '^E|' "$REGISTO")
[ "$ENTRADAS" -ge 4 ] || { echo "São precisas pelo menos 4 entradas (existem $ENTRADAS)."; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Linhas (no ficheiro) da 2.ª e 3.ª entradas E.
L2=$(grep -n '^E|' "$REGISTO" | sed -n 2p | cut -d: -f1)
L3=$(grep -n '^E|' "$REGISTO" | sed -n 3p | cut -d: -f1)

# 1) Alterar: troca o tipo de evento da 2.ª entrada, mantendo o hash.
awk -F'|' -v OFS='|' -v n="$L2" 'NR==n{$4="ADULTERADO"}1' "$REGISTO" > "$TMP/alterado.log"
# 2) Remover: apaga a 2.ª entrada.
sed "${L2}d" "$REGISTO" > "$TMP/removido.log"
# 3) Reordenar: troca a 2.ª e a 3.ª entradas.
awk -v a="$L2" -v b="$L3" 'NR==FNR{l[NR]=$0;next} FNR==a{print l[b];next} FNR==b{print l[a];next} 1' "$REGISTO" "$REGISTO" > "$TMP/reordenado.log"

falhas=0
correr() {
  local nome=$1 ficheiro=$2 esperado=$3
  echo "== $nome =="
  "${VERIFICAR[@]}" "$ficheiro" "$CERT_RELAY" "$CA"
  local codigo=$?
  if [ "$codigo" -eq "$esperado" ]; then echo "-> OK (esperado $esperado)"; else echo "-> FALHOU (código $codigo, esperado $esperado)"; falhas=1; fi
  echo
}

correr "Registo original"       "$REGISTO"            0
correr "Entrada alterada"       "$TMP/alterado.log"   1
correr "Entrada removida"       "$TMP/removido.log"   1
correr "Entradas reordenadas"   "$TMP/reordenado.log" 1

exit $falhas
