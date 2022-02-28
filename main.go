package main

import (
	"fmt"
	"net/http"

	"github.com/NBISweden/sda-uppmax-integration/projects"
	"github.com/NBISweden/sda-uppmax-integration/token"
)

func main() {

	http.HandleFunc("/projects", projects.BasicAuth(projects.GetProjects))
	http.HandleFunc("/token", token.GetToken)

	fmt.Println("Starting server at port 8080")
	http.ListenAndServe(":8080", nil)

}
