package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"slices"

	"gitea.m8anis.internal/M8Anis/go-ocsp-service/service"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var (
	_address string
	_port    uint16

	_db_path string

	_cert_path, _priv_path string
	_issuer_path           string
)

var (
	_cert, _issuer *x509.Certificate
	_priv          crypto.Signer
)

func init() {
	flag.StringVarP(&_db_path, "database", "d", "./db", "Path to database store")

	flag.StringVarP(&_issuer_path, "ca-certificate", "i", "./certs/issuer.pem", "Path to CA that issued responder certificate")
	flag.StringVarP(&_cert_path, "certificate", "c", "./certs/responder.pem", "Path to responder certificate")
	flag.StringVarP(&_priv_path, "key", "k", "./private/key.pem", "Path to responder certificate private key")

	flag.StringVarP(&_address, "address", "a", "127.251.209.16", "IP to run on")
	flag.Uint16VarP(&_port, "port", "p", 19721, "Port to run on")

	flag.Parse()
}

func init() {
	if certFile, err := os.ReadFile(_cert_path); err == nil {
		pemCert, _ := pem.Decode(certFile)

		if _cert, err = x509.ParseCertificate(pemCert.Bytes); err != nil {
			logrus.Fatalf("Cannot parse responder certificate: %s", err)
		}
	} else {
		logrus.Fatalf("Cannot read responder certificate: %s", err)
	}

	if (_cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		logrus.Fatalf("Responder certificate can't be used for signing (No `Digital Signature` in key usage)")
	}

	if !slices.Contains(_cert.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		logrus.Fatalf("Responder certificate can't be used for OCSP signing (No `OCSP signing` in extended key usage)")
	}

	if privFile, err := os.ReadFile(_priv_path); err == nil {
		pemPriv, _ := pem.Decode(privFile)

		var ecParseError, rsaParseError error

		if _priv, ecParseError = x509.ParseECPrivateKey(pemPriv.Bytes); ecParseError != nil {
			if _priv, rsaParseError = x509.ParsePKCS1PrivateKey(pemPriv.Bytes); rsaParseError != nil {
				logrus.Fatalf("Cannot parse responder private key.\nEC: %s; RSA: %s", ecParseError, rsaParseError)
			}
		}
	} else {
		logrus.Fatalf("Cannot read responder private key: %s", err)
	}

	pubKeyMatch := true
	switch _cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		pubKeyMatch = _cert.PublicKey.(*ecdsa.PublicKey).Equal(_priv.Public().(*ecdsa.PublicKey))
	case *rsa.PublicKey:
		pubKeyMatch = _cert.PublicKey.(*rsa.PublicKey).Equal(_priv.Public().(*rsa.PublicKey))
	default:
		logrus.Warn("Certificate public key and public key in private key not checked. Unknown public key type")
	}
	if !pubKeyMatch {
		logrus.Fatalf("Public key in responder certificate does not match public key in provided private key")
	}

	if caCertFile, err := os.ReadFile(_issuer_path); err == nil {
		pemCaCert, _ := pem.Decode(caCertFile)

		if _issuer, err = x509.ParseCertificate(pemCaCert.Bytes); err != nil {
			logrus.Fatalf("Cannot parse CA certificate: %s", err)
		}
	} else {
		logrus.Fatalf("Cannot read CA certificate: %s", err)
	}

	if err := _cert.CheckSignatureFrom(_issuer); err != nil {
		logrus.Fatalf("Responder certificate not been issued by gived CA")
	}
}

func main() {
	service.Serve(
		fmt.Sprintf("%s:%d", _address, _port),
		_db_path,
		_issuer, _cert, _priv,
	)
}
