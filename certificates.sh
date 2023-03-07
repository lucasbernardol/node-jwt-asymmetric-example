### Run "./certificates.sh" or "node crypto.config.js" 

openssl genpkey -aes-256-cbc -pass file:./tmp/passphrase.txt -algorithm RSA -outform PEM -out ./tmp/certificates/private.pem \
  -pkeyopt rsa_keygen_bits:3072

openssl pkey -inform PEM -in ./tmp/certificates/private.pem -outform PEM -passin file:./tmp/passphrase.txt --pubout -out ./tmp/certificates/public.pem