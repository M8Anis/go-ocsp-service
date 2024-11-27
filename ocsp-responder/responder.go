package ocspresponder

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"net/http"
	"slices"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type RetrieveError struct {
	Code int
	Body []byte
}

type OCSPResponder struct {
	CaCertificate, Certificate *x509.Certificate
	PrivateKey                 crypto.Signer

	Database *badger.DB
	Server   *http.Server
}

func (responder *OCSPResponder) MakeResponse(derReq []byte) (derResp []byte, retrieveErr *RetrieveError) {
	req, err := ocsp.ParseRequest(derReq)
	if err != nil {
		logrus.Infof("Request can't be parsed: %s", err)
		retrieveErr = &RetrieveError{
			Code: http.StatusBadRequest,
			Body: ocsp.MalformedRequestErrorResponse,
		}
		return
	}

	if !responder.Valid(req) {
		logrus.Info("Misdirected request")
		retrieveErr = &RetrieveError{
			Code: http.StatusMisdirectedRequest,
			Body: ocsp.MalformedRequestErrorResponse,
		}
		return
	}

	var status, resp []byte

	if err := responder.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get(req.SerialNumber.Bytes())
		if err != nil {
			return err
		}

		status, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		if err == badger.ErrKeyNotFound {
			if resp, err = responder.Response(&ocsp.Response{
				SerialNumber: req.SerialNumber,
				Status:       ocsp.Unknown,
				ThisUpdate:   time.Now(),
				NextUpdate:   time.Now().AddDate(0, 0, 1).Add(-time.Second),
			}); err != nil {
				logrus.Errorf("Response can't be created: %s", err)
				retrieveErr = &RetrieveError{
					Code: http.StatusInternalServerError,
					Body: ocsp.InternalErrorErrorResponse,
				}
				return
			}
			logrus.Info("Certificate not found")
			retrieveErr = &RetrieveError{
				Code: http.StatusNotFound,
				Body: resp,
			}
			return
		} else {
			logrus.Errorf("Can't be retrieve certificate: %s", err)
			retrieveErr = &RetrieveError{
				Code: http.StatusInternalServerError,
				Body: ocsp.InternalErrorErrorResponse,
			}
			return
		}
	}

	switch binary.BigEndian.Uint64(status) {
	case 0:
		if derResp, err = responder.Response(&ocsp.Response{
			SerialNumber: req.SerialNumber,
			Status:       ocsp.Good,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().AddDate(0, 0, 1).Add(-time.Second),
		}); err != nil {
			logrus.Errorf("Response can't be created: %s", err)
			retrieveErr = &RetrieveError{
				Code: http.StatusInternalServerError,
				Body: ocsp.InternalErrorErrorResponse,
			}
			return
		}
	default:
		if derResp, err = responder.Response(&ocsp.Response{
			SerialNumber: req.SerialNumber,
			Status:       ocsp.Revoked,
			RevokedAt:    time.Unix(int64(binary.BigEndian.Uint64(status)), 0),
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().AddDate(0, 0, 1).Add(-time.Second),
		}); err != nil {
			logrus.Errorf("Response can't be created: %s", err)
			retrieveErr = &RetrieveError{
				Code: http.StatusInternalServerError,
				Body: ocsp.InternalErrorErrorResponse,
			}
			return
		}
	}

	return
}

// Checker Issuer hashes
func (responder *OCSPResponder) Valid(req *ocsp.Request) bool {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(responder.CaCertificate.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		logrus.Errorf("Can't be decode subject public key info: %s", err)

		return false
	}

	h := req.HashAlgorithm.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(responder.CaCertificate.RawSubject)
	issuerNameHash := h.Sum(nil)

	return slices.Equal(req.IssuerKeyHash, issuerKeyHash) && slices.Equal(req.IssuerNameHash, issuerNameHash)
}

func (responder *OCSPResponder) Response(template *ocsp.Response) (derResp []byte, err error) {
	derResp, err = ocsp.CreateResponse(responder.CaCertificate, responder.Certificate, *template, responder.PrivateKey)
	return
}
