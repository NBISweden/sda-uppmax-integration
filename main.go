package main

import (
	"fmt"
	"net/http"

	"github.com/NBISweden/sda-uppmax-integration/token"
)

func main() {

	http.HandleFunc("/token", token.BasicAuth(token.GetToken))

	fmt.Println("Starting server at port 8080")
	http.ListenAndServe(":8080", nil)

}
