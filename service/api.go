package service

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitea.m8anis.internal/M8Anis/go-ocsp-service/responder"
	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
)

const DER_CERTIFICATE_CONTENT_TYPE string = "application/pkix-cert"
const DER_REVOCATION_LIST_CONTENT_TYPE string = "application/pkix-crl"

func addNewCertificate(w http.ResponseWriter, r *http.Request) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if DER_CERTIFICATE_CONTENT_TYPE != contentType {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Mismatch `Content-Type` (%s != %s)", DER_CERTIFICATE_CONTENT_TYPE, contentType)
		return
	}

	defer r.Body.Close()
	derCert, err := io.ReadAll(r.Body)
	if err != nil {
		logrus.Errorf("Body can't be reader: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(derCert); err != nil {
		logrus.Infof("Cannot parse certificate: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Malformed certificate")
		return
	}

	if err := cert.CheckSignatureFrom(instance.CaCertificate); err != nil {
		logrus.Errorf("Incorrect certificate uploaded (%s)", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid certificate")
		return
	}

	if revokedAt, err := instance.RevocationTime(cert.SerialNumber.Bytes()); err != nil && err != badger.ErrKeyNotFound {
		logrus.Errorf("Cannot check certificate revocation: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		if !revokedAt.IsZero() {
			w.WriteHeader(http.StatusPreconditionFailed)
			fmt.Fprintf(w, "Certificate revoked at %s", revokedAt.UTC().Format(time.RFC3339))
			return
		}
	}

	if err := instance.Database.Update(func(txn *badger.Txn) error {
		err = txn.Set(cert.SerialNumber.Bytes(), responder.RAW_ZERO_TIMESTAMP)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		logrus.Errorf("Cannot add certificate to database: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}

func updateRevocationList(w http.ResponseWriter, r *http.Request) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if DER_REVOCATION_LIST_CONTENT_TYPE != contentType {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Mismatch `Content-Type` (%s != %s)", DER_REVOCATION_LIST_CONTENT_TYPE, contentType)
		return
	}

	defer r.Body.Close()
	derCrl, err := io.ReadAll(r.Body)
	if err != nil {
		logrus.Errorf("Body can't be reader: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var crl *x509.RevocationList
	if crl, err = x509.ParseRevocationList(derCrl); err != nil {
		logrus.Infof("Cannot parse revocation list: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Malformed revocation list")
		return
	}

	if err := crl.CheckSignatureFrom(instance.CaCertificate); err != nil {
		logrus.Errorf("Incorrect revocation list (%s)", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Invalid revocation list")
		return
	}

	if crl.Number.Cmp(instance.RevocationList.Number) < 0 {
		logrus.Warn("Out of order revocation list uploaded (Number in uploaded CRL less than known)")
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprint(w, "Out of order revocation list")
		return
	}

	instance.RevocationList = crl
	go instance.UpdateEntriesFromCRL()

	w.WriteHeader(http.StatusOK)
	return
}
