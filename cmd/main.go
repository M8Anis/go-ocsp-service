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
	_cacert_file string
	_crl_file    string
	_db_path     string
	_time_diff   uint32

	_address string
	_port    uint16

	_cert_file, _priv_file string
)

var (
	_crl           *x509.RevocationList
	_cacert, _cert *x509.Certificate
	_priv          crypto.Signer
)

func init() {
	flag.StringVarP(&_cacert_file, "authority-certificate", "i", "./certs/ca.pem", "Path to CA certificate that issued responder certificate")
	flag.StringVarP(&_crl_file, "revocation-list", "r", "./crl.pem", "Path to CA CRL")
	flag.StringVarP(&_db_path, "database", "d", "./db", "Path to responder database store")
	flag.Uint32VarP(&_time_diff, "time-difference", "t", 90, "Difference in minutes between ThisUpdate and NextUpdate fields")

	flag.StringVarP(&_address, "address", "a", "127.251.209.16", "IP to run on")
	flag.Uint16VarP(&_port, "port", "p", 19721, "Port to run on")

	flag.StringVarP(&_cert_file, "certificate", "c", "./certs/cert.pem", "Path to responder certificate")
	flag.StringVarP(&_priv_file, "key", "k", "./private/key.pem", "Path to responder certificate private key")

	flag.Parse()
}

func init() {
	if certFile, err := os.ReadFile(_cert_file); err == nil {
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

	if privFile, err := os.ReadFile(_priv_file); err == nil {
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

	if caCertFile, err := os.ReadFile(_cacert_file); err == nil {
		pemCaCert, _ := pem.Decode(caCertFile)

		if _cacert, err = x509.ParseCertificate(pemCaCert.Bytes); err != nil {
			logrus.Fatalf("Cannot parse CA certificate: %s", err)
		}
	} else {
		logrus.Fatalf("Cannot read CA certificate: %s", err)
	}

	if err := _cert.CheckSignatureFrom(_cacert); err != nil {
		logrus.Fatalf("Responder certificate not been issued by gived CA (%s)", err)
	}

	if crlFile, err := os.ReadFile(_crl_file); err == nil {
		pemCrl, _ := pem.Decode(crlFile)

		if _crl, err = x509.ParseRevocationList(pemCrl.Bytes); err != nil {
			logrus.Fatalf("Cannot parse revocation list: %s", err)
		}
	} else {
		logrus.Fatalf("Cannot read revocation list: %s", err)
	}

	if err := _crl.CheckSignatureFrom(_cacert); err != nil {
		logrus.Fatalf("Revocation list not been created by gived CA (%s)", err)
	}
}

func main() {
	service.Serve(
		fmt.Sprintf("%s:%d", _address, _port),
		_db_path,
		_crl, _cacert,
		_cert, _priv,
		_time_diff,
	)
}
