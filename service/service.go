package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func Serve(host, dbPath string, caCert, responderCert *x509.Certificate, responderPrivkey crypto.Signer) {
	// Database
	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		logrus.Fatal(err)
	}
	defer db.Close()

	// OCSP
	resp := ocsp.Response{}

	// HTTP
	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", resp.Raw)
	})

	s := &http.Server{
		Handler: r,

		Addr: host,
	}

	go func() {
		s.ListenAndServe()
	}()

	// Wait to close
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	// Closing
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)
}
