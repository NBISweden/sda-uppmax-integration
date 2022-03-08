package main

import (
	"fmt"
	"net/http"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	"github.com/NBISweden/sda-uppmax-integration/token"
	log "github.com/sirupsen/logrus"
)

func ping(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Pong")
}

func main() {

	err := helpers.NewConf(&helpers.Config)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/token", helpers.BasicAuth(token.GetToken))
	http.HandleFunc("/ping", ping)

	fmt.Println("Starting server at port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
