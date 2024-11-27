package main

import (
	"flag"

	"gitea.m8anis.internal/M8Anis/go-ocsp-service/service"
)

func init() {
	flag.Parse()
}

func main() {
	service.Serve()
}
