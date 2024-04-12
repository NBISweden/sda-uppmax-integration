package token

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	b64 "encoding/base64"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

type tokenRequest struct {
	SwamID    string `json:"swamid"`
	ProjectID string `json:"projectid"`
}

type tokenResponse struct {
	SwamID      string `json:"swamid"`
	ProjectID   string `json:"projectid"`
	RequestTime string `json:"request_time"`
	Expiration  string `json:"expiration"`
	S3Config    string `json:"s3config"`
	Crypt4ghKey string `json:"crypt4gh_key"`
}

func readRequestBody(body io.ReadCloser) (tokenRequest tokenRequest, err error) {

	err = json.NewDecoder(body).Decode(&tokenRequest)
	if err != nil {
		return tokenRequest, err
	}

	if tokenRequest.ProjectID == "" || tokenRequest.SwamID == "" {
		return tokenRequest, fmt.Errorf("incomplete incoming data")
	}

	return tokenRequest, nil
}

func createECToken(key *ecdsa.PrivateKey, username string) (string, error) {
	// signing method of token
	token := jwt.New(jwt.SigningMethodES256)
	// token headers
	token.Header["alg"] = "ES256"
	token.Header["kid"] = "sda"
	// token claims
	claims := make(jwt.MapClaims)
	claims["iss"] = helpers.Config.Iss
	claims["exp"] = time.Now().AddDate(0, 0, helpers.Config.ExpirationDays).Unix()
	claims["sub"] = username
	claims["pilot"] = helpers.Config.Username
	token.Claims = claims

	// create token
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func createS3Config(username string) (s3config string, expiration string, err error) {
	s3config = "guess_mime_type = True\n" +
		"human_readable_sizes = True\n" +
		"use_https = True\n" +
		"multipart_chunk_size_mb = 50\n" +
		"check_ssl_certificate = True\n" +
		"check_ssl_hostname = True\n" +
		"encoding = UTF-8\n" +
		"encrypt = False\n" +
		"socket_timeout = 30\n"

	token, err := createECToken(helpers.Config.JwtParsedKey, username)
	if err != nil {
		return "", "", err
	}

	expiration = time.Now().AddDate(0, 0, helpers.Config.ExpirationDays).Format("01-02-2006 15:04:05")
	s3config += "secret_key = " + strings.ReplaceAll(username, "@", "_") + "\naccess_key = " + strings.ReplaceAll(username, "@", "_") +
		"\naccess_token = " + token + "\nhost_base = " + helpers.Config.S3URL + "\nhost_bucket = " + helpers.Config.S3URL

	s3config = b64.StdEncoding.EncodeToString([]byte(s3config))

	return s3config, expiration, nil
}

// createResponse is populating the struct that contains the response to the request by
// adding values to the fields and creating an S3 configuration file
func createResponse(tokenRequest tokenRequest, username string) (tokenResponse tokenResponse, err error) {

	tokenResponse.RequestTime = time.Now().Format("01-02-2006 15:04:05")
	tokenResponse.SwamID = tokenRequest.SwamID
	tokenResponse.ProjectID = tokenRequest.ProjectID
	tokenResponse.Crypt4ghKey = helpers.Config.Crypt4ghKey

	tokenResponse.S3Config, tokenResponse.Expiration, err = createS3Config(username)
	if err != nil {
		return tokenResponse, fmt.Errorf("error creating S3 configuration")
	}

	return tokenResponse, err
}

// GetToken returns the information require for uploading data to the S3 backend,
// including the token
func GetToken(w http.ResponseWriter, r *http.Request) {

	tokenRequest, err := readRequestBody(r.Body)

	// sanitize inputs just in case (and to make CodeQL happy)
	swamID := strings.ReplaceAll(tokenRequest.SwamID, "\n", "")
	swamID = strings.ReplaceAll(swamID, "\r", "")

	projectID := strings.ReplaceAll(tokenRequest.ProjectID, "\n", "")
	projectID = strings.ReplaceAll(projectID, "\r", "")

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != nil {
		currentError := helpers.CreateErrorResponse("Error reading request body - " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return

	}

	// Check specified swam_id against project_id
	err = verifyEGABoxAccount(swamID)
	if err != nil {
		log.Infof("%v is not a valid ega account", swamID)
		currentError := helpers.CreateErrorResponse("Unauthorized to access specified project")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return

	}
	log.Infof("%v is verified as existing ega account", swamID)

	err = verifyProjectAccount(swamID, projectID)
	if err != nil {

		log.Infof("%v is not the PI of SUPR project %v", swamID, projectID)
		currentError := helpers.CreateErrorResponse("Unauthorized to access specified project")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return
	}
	log.Infof("%v verified as the PI of SUPR project %v", swamID, projectID)

	// Create token for user corresponding to specified swam_id
	resp, err := createResponse(tokenRequest, swamID)
	if err != nil {
		currentError := helpers.CreateErrorResponse("Unable to create token for specified project")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, string(currentError))

		return
	}

	response, _ := json.Marshal(resp)

	fmt.Fprint(w, string(response))

}
