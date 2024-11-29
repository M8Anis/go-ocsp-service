package service

import (
	"crypto/x509"
	"io"
	"net/http"
	"strings"

	"gitea.m8anis.internal/M8Anis/go-ocsp-service/responder"
	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
)

const DER_CERTIFICATE_CONTENT_TYPE string = "application/pkix-cert"
const DER_REVOCATION_LIST_CONTENT_TYPE string = "application/pkix-crl"

func addNewCertificate(w http.ResponseWriter, r *http.Request) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if DER_CERTIFICATE_CONTENT_TYPE != contentType {
		w.WriteHeader(http.StatusUnsupportedMediaType)
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
		return
	}

	if err := cert.CheckSignatureFrom(instance.CaCertificate); err != nil {
		logrus.Errorf("Incorrect certificate uploaded (%s)", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if revokedAt, err := instance.RevocationTime(cert.SerialNumber.Bytes()); err == nil {
		if revokedAt.IsZero() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusPreconditionFailed)
		}
		return
	} else if err != badger.ErrKeyNotFound {
		logrus.Errorf("Cannot check certificate revocation: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
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

	w.WriteHeader(http.StatusCreated)
	return
}

func updateRevocationList(w http.ResponseWriter, r *http.Request) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if DER_REVOCATION_LIST_CONTENT_TYPE != contentType {
		w.WriteHeader(http.StatusUnsupportedMediaType)
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
		return
	}

	if err := crl.CheckSignatureFrom(instance.CaCertificate); err != nil {
		logrus.Errorf("Incorrect revocation list (%s)", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch crl.Number.Cmp(instance.RevocationList.Number) {
	case -1:
		logrus.Warn("Out of order revocation list uploaded (Number in uploaded CRL less than known)")
		w.WriteHeader(http.StatusConflict)
		return
	case 0:
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		break
	}

	instance.RevocationList = crl
	go instance.UpdateEntriesFromCRL()

	w.WriteHeader(http.StatusOK)
	return
}
