package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"os"
	"os/signal"
	"time"

	"gitea.m8anis.internal/M8Anis/go-ocsp-service/responder"
	"github.com/dgraph-io/badger/v4"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var instance *responder.OCSPResponder

func Serve(host, dbPath string, caCrl *x509.RevocationList, caCert, responderCert *x509.Certificate, responderPrivkey crypto.Signer) {
	r := mux.NewRouter()
	registerRoutes(r)

	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		logrus.Fatal(err)
	}
	defer db.Close()

	instance = &responder.OCSPResponder{
		RevocationList: caCrl,
		CaCertificate:  caCert,

		Certificate: responderCert,
		PrivateKey:  responderPrivkey,

		Database: db,
		Server: &http.Server{
			Handler: r,
			Addr:    host,
		},
	}
	instance.UpdateEntriesFromCRL()

	go func() {
		instance.Server.ListenAndServe()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	instance.Server.Shutdown(ctx)
}

func registerRoutes(r *mux.Router) {
	r.HandleFunc("/", handleRequest).
		Methods(http.MethodPost)

	r.UseEncodedPath().
		HandleFunc("/{b64Req}", handleRequestInURL).
		Methods(http.MethodGet)

	r.HandleFunc("/api/certificate", addNewCertificate).
		Methods(http.MethodPut)

	r.HandleFunc("/api/revocation-list", updateRevocationList).
		Methods(http.MethodPut)
}
