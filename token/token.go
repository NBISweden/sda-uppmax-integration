package token

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
)

type tokenRequest struct {
	Swamid    string `json:"swamid"`
	ProjectID string `json:"projectid"`
}

type tokenResponse struct {
	Swamid      string    `json:"swamid"`
	ProjectID   string    `json:"projectid"`
	RequestTime time.Time `json:"request_time"`
	Expiration  time.Time `json:"expiration"`
	S3Config    string    `json:"s3config"`
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

func createS3Config(s string) (s3config string, expiration time.Time, err error) {
	panic("unimplemented")
}

func createResponse(tokenRequest tokenRequest) (tokenResponse tokenResponse, err error) {

	tokenResponse.RequestTime = time.Now()
	tokenResponse.Swamid = tokenRequest.Swamid
	tokenResponse.ProjectID = tokenRequest.ProjectID

	tokenResponse.S3Config, tokenResponse.Expiration, err = createS3Config(tokenRequest.Swamid)
	if err != nil {
		return tokenResponse, fmt.Errorf("Error creating S3 configuration")
	}

	return tokenResponse, err
}

func GetToken(w http.ResponseWriter, r *http.Request) {

	tokenRequest, err := readRequestBody(r.Body)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != nil {
		currentError := helpers.CreateErrorResponse("Error reading request body - " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))
	}

	// Check specified swam_id against project_id

	// Create token for user corresponding to specified swam_id

	response, _ := json.Marshal(tokenRequest)

	fmt.Fprintln(w, string(response))

}
