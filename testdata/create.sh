mkdir -p private certs

certtool --generate-privkey --key-type ecc --curve secp256r1 --no-text --outfile private/ca-key.pem
certtool --generate-self-signed --load-privkey private/ca-key.pem --outfile certs/issuer.pem --template ca.cfg --hash=sha256

certtool --generate-crl --load-ca-privkey private/ca-key.pem --load-ca-certificate certs/issuer.pem --template crl.cfg \
    --outfile crl.pem --hash=sha256

certtool --generate-privkey --key-type ecc --curve secp256r1 --no-text --outfile private/key.pem
certtool --generate-certificate --load-ca-privkey private/ca-key.pem  --load-ca-certificate certs/issuer.pem \
    --load-privkey private/key.pem --outfile certs/responder.pem --template ocsp.cfg --hash=sha256

#mv crl.pem prev-crl.pem
#certtool --generate-crl --load-crl prev-crl.pem --load-ca-privkey private/ca-key.pem --load-ca-certificate certs/issuer.pem \
#   --template crl.cfg --outfile crl.pem --hash=sha256 --load-certificate certs/responder.pem
