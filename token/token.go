package token

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	b64 "encoding/base64"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	"github.com/golang-jwt/jwt"
)

type tokenRequest struct {
	Swamid    string `json:"swamid"`
	ProjectID string `json:"projectid"`
}

type tokenResponse struct {
	Swamid      string `json:"swamid"`
	ProjectID   string `json:"projectid"`
	RequestTime string `json:"request_time"`
	Expiration  string `json:"expiration"`
	S3Config    string `json:"s3config"`
}

func readRequestBody(body io.ReadCloser) (tokenRequest tokenRequest, err error) {

	reqBody, err := ioutil.ReadAll(body)
	if err != nil {
		return tokenRequest, fmt.Errorf("Error reading request body")
	}
	defer body.Close()

	err = json.Unmarshal(reqBody, &tokenRequest)
	if err != nil {
		return tokenRequest, fmt.Errorf("Error unmarshaling data")
	}

	if tokenRequest.ProjectID == "" || tokenRequest.Swamid == "" {
		return tokenRequest, fmt.Errorf("Incomplete incoming data")
	}

	return tokenRequest, nil
}

func createECToken(key *ecdsa.PrivateKey, username string) (string, error) {
	// signing method of token
	token := jwt.New(jwt.SigningMethodES256)
	// token headers
	token.Header["alg"] = "ES256"
	// token claims
	claims := make(jwt.MapClaims)
	claims["iss"] = helpers.Config.Iss

	claims["exp"] = time.Now().AddDate(0, 0, helpers.Config.ExpirationDays).Unix()
	claims["sub"] = username
	token.Claims = claims

	// create token
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func createS3Config(username string) (s3config string, expiration string, err error) {
	s3config = "guess_mime_type = True \nhuman_readable_sizes = True\nuse_https = True\n" +
		"multipart_chunk_size_mb = 50\n" + "check_ssl_certificate = True\n" +
		"check_ssl_hostname = True\n" + "encoding = UTF-8\n" + "encrypt = False\n" +
		"socket_timeout = 30\n"

	token, err := createECToken(helpers.Config.ParsedKey, username)
	if err != nil {
		return "", "", err
	}

	expiration = time.Now().AddDate(0, 0, helpers.Config.ExpirationDays).Format("01-02-2006 15:04:05")
	s3config += "secret_key = " + username + "\naccess_key = " + username + "\naccess_token = " + token +
		"\nhost_base = " + helpers.Config.S3URL + "\nhost_bucket = " + helpers.Config.S3URL

	s3config = b64.StdEncoding.EncodeToString([]byte(s3config))

	return s3config, expiration, nil
}

func createResponse(tokenRequest tokenRequest, username string) (tokenResponse tokenResponse, err error) {

	tokenResponse.RequestTime = time.Now().Format("01-02-2006 15:04:05")
	tokenResponse.Swamid = tokenRequest.Swamid
	tokenResponse.ProjectID = tokenRequest.ProjectID

	tokenResponse.S3Config, tokenResponse.Expiration, err = createS3Config(username)
	if err != nil {
		return tokenResponse, fmt.Errorf("Error creating S3 configuration")
	}

	return tokenResponse, err
}

// getEGABoxAccount checks whether the access for the specified swamID and project is granted
// and returns the respective ega-box account
func getEGABoxAccount(projectID string, swamID string) (username string, err error) {

	username = helpers.Config.EgaUser

	if err != nil {
		return "", err
	}

	return username, nil
}

// GetToken returns the information require for uploading data to the S3 backend,
// including the token
func GetToken(w http.ResponseWriter, r *http.Request) {

	tokenRequest, err := readRequestBody(r.Body)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != nil {
		currentError := helpers.CreateErrorResponse("Error reading request body - " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return

	}

	// Check specified swam_id against project_id
	username, err := getEGABoxAccount(tokenRequest.ProjectID, tokenRequest.Swamid)
	if err != nil {
		currentError := helpers.CreateErrorResponse("Unauthorized to access specified project")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return

	}

	// Create token for user corresponding to specified swam_id
	resp, err := createResponse(tokenRequest, username)
	if err != nil {
		currentError := helpers.CreateErrorResponse("Unable to create token for specified project")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return
	}

	response, _ := json.Marshal(resp)

	fmt.Fprint(w, string(response))

}
