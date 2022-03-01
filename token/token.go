package token

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
)

var Username = "uppmax"
var Password = "uppmax"

type tokenRequest struct {
	Swamid    string `json:"swamid"`
	ProjectID string `json:"projectid"`
}

func readRequestBody(body io.ReadCloser) (tokenRequest tokenRequest, err error) {

	reqBody, err := ioutil.ReadAll(body)
	if err != nil {
		return tokenRequest, fmt.Errorf("Reading request body")
	}
	defer body.Close()

	err = json.Unmarshal(reqBody, &tokenRequest)
	if err != nil {
		return tokenRequest, fmt.Errorf("Unmarshaling data")
	}

	if tokenRequest.ProjectID == "" || tokenRequest.Swamid == "" {
		return tokenRequest, fmt.Errorf("Incomplete data")
	}

	return tokenRequest, nil
}

func GetToken(w http.ResponseWriter, r *http.Request) {

	tokenRequest, err := readRequestBody(r.Body)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != nil {
		currentError := helpers.CreateErrorResponse("Error reading request body - " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))
	}

	response, _ := json.Marshal(tokenRequest)

	fmt.Fprintln(w, string(response))

}
