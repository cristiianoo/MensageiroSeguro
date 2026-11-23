#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
java -cp out pt.ua.estga.mensageiro.seguranca.TesteEnvelope
