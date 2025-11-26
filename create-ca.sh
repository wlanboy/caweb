cd /local-ca

#prime256v1 (NIST P‑256) oder secp384r1 (NIST P‑384)
#openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl ecparam -name secp384r1 -genkey -noout -out ca.key

openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.pem -subj "/C=DE/ST=Germany/L=LAN/O=Homelab CA/CN=Homelab Root CA"
