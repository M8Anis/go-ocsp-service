package service

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	derReq, err := io.ReadAll(r.Body)
	if err != nil {
		logrus.Errorf("Body can't be reader: %s", err)
		sendResponse(w, http.StatusInternalServerError, ocsp.InternalErrorErrorResponse)
		return
	}

	derResp, creationErr := instance.MakeResponse(derReq)
	if creationErr != nil {
		sendResponse(w, creationErr.Code, creationErr.Body)
		return
	}
	sendResponse(w, http.StatusOK, derResp)
}

func handleRequestInURL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	pemReq := vars["b64Req"]
	derReq, err := base64.StdEncoding.DecodeString(pemReq)
	if err != nil {
		logrus.Infof("PEM request can't be decoded: %s", err)
		sendResponse(w, http.StatusBadRequest, ocsp.MalformedRequestErrorResponse)
		return
	}

	derResp, creationErr := instance.MakeResponse(derReq)
	if creationErr != nil {
		sendResponse(w, creationErr.Code, creationErr.Body)
		return
	}
	sendResponse(w, http.StatusOK, derResp)
}

func sendResponse(w http.ResponseWriter, statusCode int, ocspResponse []byte) {
	w.Header().Add("Content-Type", "application/ocsp-response")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "%s", ocspResponse)
}
