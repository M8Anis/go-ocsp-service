package responder

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"slices"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

// MarshalBinary of zeroed time.Time
var RAW_ZERO_TIMESTAMP = []byte{
	0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xFF, 0xFF,
}

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

	if !responder.issuerIsValid(req) {
		logrus.Info("Misdirected request")
		retrieveErr = &RetrieveError{
			Code: http.StatusMisdirectedRequest,
			Body: ocsp.MalformedRequestErrorResponse,
		}
		return
	}

	var revokedAt time.Time

	if revokedAt, err = responder.RevocationTime(req.SerialNumber.Bytes()); err != nil {
		if err == badger.ErrKeyNotFound {
			var resp []byte
			if resp, err = responder.response(req.SerialNumber, ocsp.Unknown); err != nil {
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
			logrus.Errorf("Cannot retrieve certificate: %s", err)
			retrieveErr = &RetrieveError{
				Code: http.StatusInternalServerError,
				Body: ocsp.InternalErrorErrorResponse,
			}
			return
		}
	}

	if revokedAt.IsZero() {
		derResp, err = responder.response(req.SerialNumber, ocsp.Good)
	} else {
		derResp, err = responder.revokedResponse(req.SerialNumber, revokedAt)
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
func (responder *OCSPResponder) issuerIsValid(req *ocsp.Request) bool {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(responder.CaCertificate.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		logrus.Errorf("Cannot decode subject public key info: %s", err)

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

func (responder *OCSPResponder) response(serialNumber *big.Int, status int) (derResp []byte, err error) {
	switch status {
	case ocsp.Good:
	case ocsp.Unknown:
		break
	default:
		logrus.Fatalf("Uncorrect response status (%d)", status)
	}

	return responder.createResponse(&ocsp.Response{
		SerialNumber: serialNumber,
		Status:       status,
	})
}

func (responder *OCSPResponder) revokedResponse(serialNumber *big.Int, at time.Time) (derResp []byte, err error) {
	return responder.createResponse(&ocsp.Response{
		SerialNumber: serialNumber,
		Status:       ocsp.Revoked,

		RevokedAt:        at,
		RevocationReason: ocsp.Unspecified,
	})
}

func (responder *OCSPResponder) createResponse(template *ocsp.Response) (derResp []byte, err error) {
	template.ThisUpdate = time.Now()
	derResp, err = ocsp.CreateResponse(responder.CaCertificate, responder.Certificate, *template, responder.PrivateKey)
	return
}

func (responder *OCSPResponder) UpdateEntriesFromCRL() {
	responder.Database.Update(func(txn *badger.Txn) error {
		for _, entry := range responder.RevocationList.RevokedCertificateEntries {
			if timeEncoded, err := entry.RevocationTime.MarshalBinary(); err == nil {
				err = txn.Set(entry.SerialNumber.Bytes(), timeEncoded)
				if err != nil {
					logrus.Errorf("Cannot set revocation date in entry: %s", err)
				}
			} else {
				logrus.Errorf("Cannot encode revocation date: %s", err)
			}
		}

		return nil
	})
}

func (responder *OCSPResponder) RevocationTime(certificateSerial []byte) (at time.Time, err error) {
	err = responder.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get(certificateSerial)
		if err != nil {
			return err
		}

		rawRevokeTime, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		if err := at.UnmarshalBinary(rawRevokeTime); err != nil {
			return err
		}

		return nil
	})

	return
}
