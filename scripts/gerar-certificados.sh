#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
command -v keytool >/dev/null || { echo 'É necessário o keytool do JDK 21.'; exit 1; }
if [ -e certificados ]; then
  echo 'A pasta certificados já existe. Nada foi alterado. Usa uma extração nova para gerar outras identidades.'
  exit 1
fi
printf 'Preparação de identidades novas apenas para demonstração local.\n'
printf 'Neste ambiente de demonstração, todos os PKCS12 usarão a palavra-passe que escolheres.\n'
read -r -s -p 'Palavra-passe de demonstração (mínimo 6 caracteres): ' G09_DEMO_PASSWORD
printf '\n'
read -r -s -p 'Repete a palavra-passe: ' G09_CONFIRM
printf '\n'
[ "${#G09_DEMO_PASSWORD}" -ge 6 ] || { echo 'Palavra-passe demasiado curta.'; exit 1; }
[ "$G09_DEMO_PASSWORD" = "$G09_CONFIRM" ] || { echo 'As palavras-passe não coincidem.'; exit 1; }
unset G09_CONFIRM
export G09_DEMO_PASSWORD
trap 'unset G09_DEMO_PASSWORD' EXIT
mkdir -p certificados/{ca,publicos,identidades,confianca}
keytool -genkeypair -alias ca-grupo09 -keyalg RSA -keysize 3072 \
 -sigalg SHA256withRSA -dname 'CN=CA Grupo 09, OU=Seguranca Informatica, O=ESTGA' \
 -validity 365 -ext BC:critical=ca:true -ext KU:critical=keyCertSign,cRLSign \
 -storetype PKCS12 -keystore certificados/ca/ca-grupo09.p12 \
 -storepass:env G09_DEMO_PASSWORD -keypass:env G09_DEMO_PASSWORD
keytool -exportcert -alias ca-grupo09 -keystore certificados/ca/ca-grupo09.p12 \
 -storepass:env G09_DEMO_PASSWORD -rfc -file certificados/publicos/ca-grupo09.crt
for nome in relay joao cristiano; do
 if [ "$nome" = relay ]; then
  dn='CN=localhost, OU=Relay, O=ESTGA'; eku=serverAuth
  uso=digitalSignature; algoritmo=SHA384withRSA
 else
  dn="CN=$nome, OU=Clientes, O=ESTGA"; eku=clientAuth
  uso=digitalSignature,keyEncipherment; algoritmo=SHA256withRSA
 fi
 keytool -genkeypair -alias "$nome" -keyalg RSA -keysize 3072 -sigalg SHA256withRSA \
  -dname "$dn" -validity 365 -storetype PKCS12 \
  -keystore "certificados/identidades/$nome.p12" \
  -storepass:env G09_DEMO_PASSWORD -keypass:env G09_DEMO_PASSWORD
 keytool -certreq -alias "$nome" -keystore "certificados/identidades/$nome.p12" \
  -storepass:env G09_DEMO_PASSWORD -file "certificados/publicos/$nome.csr"
 extra=()
 if [ "$nome" = relay ]; then extra=(-ext SAN=dns:localhost,ip:127.0.0.1); fi
 keytool -gencert -alias ca-grupo09 -keystore certificados/ca/ca-grupo09.p12 \
  -storepass:env G09_DEMO_PASSWORD -infile "certificados/publicos/$nome.csr" \
  -outfile "certificados/publicos/$nome.crt" -rfc -validity 365 \
  -sigalg "$algoritmo" -ext BC:critical=ca:false -ext "KU:critical=$uso" \
  -ext "EKU=$eku" "${extra[@]}"
 # A CA importada é a que este próprio script acabou de gerar.
 keytool -importcert -noprompt -alias ca-grupo09 \
  -file certificados/publicos/ca-grupo09.crt \
  -keystore "certificados/identidades/$nome.p12" -storepass:env G09_DEMO_PASSWORD
 keytool -importcert -alias "$nome" -file "certificados/publicos/$nome.crt" \
  -keystore "certificados/identidades/$nome.p12" -storepass:env G09_DEMO_PASSWORD
done
keytool -importcert -noprompt -alias ca-grupo09 -file certificados/publicos/ca-grupo09.crt \
 -storetype PKCS12 -keystore certificados/confianca/confianca.p12 \
 -storepass:env G09_DEMO_PASSWORD
printf '\nPreparação concluída. Usa a palavra-passe escolhida nos pedidos de identidade e confiança.\n'
printf 'A chave da CA não é necessária para executar o cliente ou o relay.\n'
