package service

import (
	"context"
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

func Serve() {
	// Database
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
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

		Addr: "127.251.209.16:19721",
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
