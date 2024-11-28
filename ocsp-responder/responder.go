package ocspresponder

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
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
	RevocationList             *x509.RevocationList
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

	var rawRevokeTime, resp []byte

	if err := responder.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get(req.SerialNumber.Bytes())
		if err != nil {
			return err
		}

		rawRevokeTime, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		if err == badger.ErrKeyNotFound {
			if resp, err = responder.Response(req.SerialNumber, ocsp.Unknown); err != nil {
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

	var revokedAt time.Time
	if err := revokedAt.UnmarshalBinary(rawRevokeTime); err != nil {
		logrus.Errorf("Can't be decode revocation date: %s", err)
		retrieveErr = &RetrieveError{
			Code: http.StatusInternalServerError,
			Body: ocsp.InternalErrorErrorResponse,
		}
		return
	}

	switch revokedAt.Unix() {
	case 0:
		derResp, err = responder.Response(req.SerialNumber, ocsp.Good)
	default:
		derResp, err = responder.ResponseRevoked(req.SerialNumber, revokedAt)
	}

	if err != nil {
		logrus.Errorf("Response can't be created: %s", err)
		retrieveErr = &RetrieveError{
			Code: http.StatusInternalServerError,
			Body: ocsp.InternalErrorErrorResponse,
		}
		return
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

func (responder *OCSPResponder) Response(serialNumber *big.Int, status int) (derResp []byte, err error) {
	switch status {
	case ocsp.Good:
	case ocsp.Unknown:
		break
	default:
		return nil, errors.New("Uncorrect response status")
	}

	return responder.createResponse(&ocsp.Response{
		SerialNumber: serialNumber,
		Status:       status,
	})
}

func (responder *OCSPResponder) ResponseRevoked(serialNumber *big.Int, at time.Time) (derResp []byte, err error) {
	return responder.createResponse(&ocsp.Response{
		SerialNumber: serialNumber,
		Status:       ocsp.Revoked,

		RevokedAt:        at,
		RevocationReason: ocsp.Unspecified,
	})
}

func (responder *OCSPResponder) createResponse(template *ocsp.Response) (derResp []byte, err error) {
	template.ThisUpdate = responder.RevocationList.ThisUpdate
	template.NextUpdate = responder.RevocationList.NextUpdate
	derResp, err = ocsp.CreateResponse(responder.CaCertificate, responder.Certificate, *template, responder.PrivateKey)
	return
}

func (responder *OCSPResponder) UpdateEntriesFromCRL() {
	responder.Database.Update(func(txn *badger.Txn) error {
		for _, entry := range responder.RevocationList.RevokedCertificateEntries {
			if binaryTime, err := entry.RevocationTime.MarshalBinary(); err == nil {
				err = txn.Set(entry.SerialNumber.Bytes(), binaryTime)
				if err != nil {
					logrus.Fatalf("Can't be set revocation date in entry: %s", err)
				}
			} else {
				logrus.Fatalf("Can't be encode revocation date: %s", err)
			}
		}

		return nil
	})
}
