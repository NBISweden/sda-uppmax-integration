package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	"github.com/NBISweden/sda-uppmax-integration/token"
	log "github.com/sirupsen/logrus"
)

func ping(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, "Pong")
}

func main() {

	err := helpers.NewConf(&helpers.Config)
	if err != nil {
		log.Fatal(err)
	}

	servicePort := 8080

	http.HandleFunc("/token", helpers.BasicAuth(token.GetToken))
	http.HandleFunc("/ping", ping)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%v", servicePort),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
	}

	log.Infof("Starting server at port %v", servicePort)
	log.Fatal(server.ListenAndServe())

}
