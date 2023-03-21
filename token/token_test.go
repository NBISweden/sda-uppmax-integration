package token

import (
	b64 "encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	"github.com/NBISweden/sda-uppmax-integration/testhelpers"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	PrivateKeyPath  string
	Crypt4ghKeyPath string
	TempDir         string
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {
	suite.TempDir, _ = os.MkdirTemp(os.TempDir(), "keys-")
	suite.PrivateKeyPath, _ = testhelpers.CreateECkeys(suite.TempDir)

	// Create random public crypt4gh key
	cryptKey := "-----BEGIN CRYPT4GH PUBLIC KEY-----\nvSome+asd/apublicKey\n-----END CRYPT4GH PUBLIC KEY-----"
	crypt4ghFile, _ := os.CreateTemp(suite.TempDir, "rsakey-")
	_, err := crypt4ghFile.Write([]byte(cryptKey))
	if err != nil {
		log.Fatal(err)
	}
	suite.Crypt4ghKeyPath = crypt4ghFile.Name()

	_ = os.WriteFile(suite.Crypt4ghKeyPath, []byte(cryptKey), 0600)

}

func (suite *TestSuite) TestNewConf() {
	expectedToken := tokenRequest{
		SwamID:    "<swamid>",
		ProjectID: "<projectid>",
	}

	r := io.NopCloser(strings.NewReader(`{
		"swamid": "<swamid>",
		"projectid": "<projectid>"
	}`))

	tokenRequest, err := readRequestBody(r)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedToken, tokenRequest)

	// Request body is not correct - missing closing bracket
	r = io.NopCloser(strings.NewReader(`{
		"swami": "<swamid>",
		"projectid": "<projectid>"
	`))

	_, err = readRequestBody(r)

	// Request body is not correct - expected swamid instead of swami
	assert.EqualError(suite.T(), err, "unexpected EOF")

	r = io.NopCloser(strings.NewReader(`{
		"swami": "<swamid>",
		"projectid": "<projectid>"
	}`))

	_, err = readRequestBody(r)

	assert.EqualError(suite.T(), err, "incomplete incoming data")
}

func (suite *TestSuite) TestCreateECToken() {

	confData := `global:
  crypt4ghKey: ` + suite.Crypt4ghKeyPath + `
  egaUsername: "some-user"
  egaPassword: "some-pass"
  egaURL: "http://ega.dev"
  expirationDays: 14
  iss: "https://some.url"
  jwtKey: "` + suite.PrivateKeyPath + `"
  suprUsername: "some-user"
  suprPassword: "some-pass"
  suprURL: "http://supr.dev"
  s3url: "some.s3.url"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
`
	configName := "config.yaml"
	err := os.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	tokenString, err := createECToken(helpers.Config.JwtParsedKey, helpers.Config.EgaUsername)
	assert.NoError(suite.T(), err)

	// Parse token to make sure it contains the correct information
	token, _ := jwt.Parse(tokenString, func(tokenElixir *jwt.Token) (interface{}, error) { return nil, nil })
	claims, _ := token.Claims.(jwt.MapClaims)

	// Check that token includes the correct information
	assert.Equal(suite.T(), helpers.Config.Username, claims["pilot"])
	assert.Equal(suite.T(), helpers.Config.Iss, claims["iss"])
	assert.Equal(suite.T(), helpers.Config.EgaUsername, claims["sub"])

	s3config, _, err := createS3Config("someuser")

	assert.NoError(suite.T(), err)

	// The S3 config base64 encode - Need to decode before running assert
	s3configDec, _ := b64.StdEncoding.DecodeString(s3config)
	assert.Contains(suite.T(), string(s3configDec), "someuser")

	defer os.Remove(configName)
}

func (suite *TestSuite) TestCreateResponse() {

	requestBody := &tokenRequest{
		ProjectID: "someproject",
		SwamID:    "someswam",
	}

	confData := `global:
  crypt4ghKey: ` + suite.Crypt4ghKeyPath + `
  egaUsername: "some-user"
  egaPassword: "some-pass"
  egaURL: "http://ega.dev"
  expirationDays: 14
  iss: "https://some.url"
  jwtKey: "` + suite.PrivateKeyPath + `"
  suprUsername: "some-user"
  suprPassword: "some-pass"
  suprURL: "http://supr.dev"
  s3url: "some.s3.url"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
`
	configName := "config.yaml"
	err := os.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	responseBody, err := createResponse(*requestBody, "someuser")
	assert.NoError(suite.T(), err)
	// Check that the base64 encoded key in the response is the expected one
	assert.Equal(suite.T(), "LS0tLS1CRUdJTiBDUllQVDRHSCBQVUJMSUMgS0VZLS0tLS0KdlNvbWUrYXNkL2FwdWJsaWNLZXkKLS0tLS1FTkQgQ1JZUFQ0R0ggUFVCTElDIEtFWS0tLS0t", responseBody.Crypt4ghKey)
	assert.Equal(suite.T(), requestBody.ProjectID, responseBody.ProjectID)
	assert.Equal(suite.T(), requestBody.SwamID, responseBody.SwamID)

	defer os.Remove(configName)
}

// TestSuccessfulVerifications uses 2 mock servers for EGA and SUPR, which return StatusOK
// and sample responses from the two endpoints, containing the same user as in the configuration
func (suite *TestSuite) TestSuccessfulVerifications() {
	ega := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{ \"header\": { \"apiVersion\": \"v1\", \"code\": 200, \"service\": \"users\", \"developerMessage\": null, \"userMessage\": \"OK\", \"errorCode\": 0, \"docLink\": \"https://ega-archive.org\" }, \"response\": { \"numTotalResults\": 1, \"resultType\": \"LocalEgaUser\", \"result\": [ { \"username\": \"some.user@nbis.se\", \"sshPublicKey\": null, \"passwordHash\": \"somePasswordHash\", \"uid\": 1234, \"gecos\": null } ] }}")
	}))
	defer ega.Close()

	supr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"matches\": [{\"id\": 1234, \"type\": \"Project\", \"name\": \"project-name\", \"title\": \"Test project\", \"directory_name\": \"\", \"directory_name_type\": \"\", \"ngi_project_name\": \"ngi-project-name\", \"abstract\": \"\", \"webpage\": \"\", \"affiliation\": \"Affiliate\", \"classification1\": \"\", \"classification2\": \"\", \"classification3\": \"\", \"managed_in_supr\": true, \"api_opaque_data\": \"\", \"ngi_sensitive_data\": true, \"ngi_ready\": false, \"ngi_delivery_status\": \"\", \"continuation_name\": \"\", \"start_date\": \"2022-09-19\", \"end_date\": \"2022-12-31\", \"pi\": {\"id\": 123, \"first_name\": \"Name\", \"last_name\": \"Lastname\", \"email\": \"some.user@nbis.se\"}, \"members\": [{\"id\": 175, \"first_name\": \"Name\", \"last_name\": \"Lastname\", \"email\": \"some.user@nbis.se\"}], \"links_outgoing\": [], \"links_incoming\": [], \"resourceprojects\": [{\"id\": 123, \"allocated\": 1000, \"resource\": {\"id\": 123, \"name\": \"Grus\", \"capacity_unit\": \"GiB\", \"capacity_unit_2\": \"\", \"centre\": {\"id\": 123, \"name\": \"UPPMAX\"}}, \"decommissioning_state\": \"N/A\", \"allocations\": [{\"id\": 123, \"start_date\": \"2022-09-19\", \"end_date\": \"2022-12-31\", \"allocated\": 1000}]}], \"modified\": \"2022-09-19 14:50:39\"}], \"began\": \"2023-02-06 13:04:31\"}")
	}))
	defer supr.Close()

	requestBody := &tokenRequest{
		ProjectID: "someproject",
		SwamID:    "some.user@nbis.se",
	}

	confData := `global:
  crypt4ghKey: ` + suite.Crypt4ghKeyPath + `
  egaUsername: "some-user"
  egaPassword: "some-pass"
  egaURL: "` + ega.URL + `"
  expirationDays: 14
  iss: "https://some.url"
  jwtKey: "` + suite.PrivateKeyPath + `"
  suprUsername: "some-user"
  suprPassword: "some-pass"
  suprURL: "` + supr.URL + `"
  s3url: "some.s3.url"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
`
	configName := "config.yaml"
	err := os.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	err = verifyEGABoxAccount(requestBody.SwamID)
	assert.NoError(suite.T(), err)

	err = verifyProjectAccount(requestBody.SwamID, requestBody.ProjectID)
	assert.NoError(suite.T(), err)

}

// TestFailedVerifications uses 2 mock servers for EGA and SUPR, which return StatusNotFound
func (suite *TestSuite) TestFailedVerifications() {
	ega := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ega.Close()

	supr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer supr.Close()

	requestBody := &tokenRequest{
		ProjectID: "someproject",
		SwamID:    "some.user@nbis.se",
	}

	confData := `global:
  crypt4ghKey: ` + suite.Crypt4ghKeyPath + `
  egaUsername: "some-user"
  egaPassword: "some-pass"
  egaURL: "` + ega.URL + `"
  expirationDays: 14
  iss: "https://some.url"
  jwtKey: "` + suite.PrivateKeyPath + `"
  suprUsername: "some-user"
  suprPassword: "some-pass"
  suprURL: "` + supr.URL + `"
  s3url: "some.s3.url"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
`
	configName := "config.yaml"
	err := os.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	err = verifyEGABoxAccount(requestBody.SwamID)
	log.Print(err)
	assert.Equal(suite.T(), fmt.Errorf("got [] from EGA"), err)

	err = verifyProjectAccount(requestBody.SwamID, requestBody.ProjectID)
	assert.Equal(suite.T(), fmt.Errorf("got [] from SUPR"), err)
}

// TestWrongSuprUser tests the case where SUPR returns a project with a user
// different than the one the request was made for
func (suite *TestSuite) TestWrongSuprUser() {
	ega := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{ \"header\": { \"apiVersion\": \"v1\", \"code\": 200, \"service\": \"users\", \"developerMessage\": null, \"userMessage\": \"OK\", \"errorCode\": 0, \"docLink\": \"https://ega-archive.org\" }, \"response\": { \"numTotalResults\": 1, \"resultType\": \"LocalEgaUser\", \"result\": [ { \"username\": \"some.user@nbis.se\", \"sshPublicKey\": null, \"passwordHash\": \"somePasswordHash\", \"uid\": 1234, \"gecos\": null } ] }}")
	}))
	defer ega.Close()

	supr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"matches\": [{\"id\": 1234, \"type\": \"Project\", \"name\": \"project-name\", \"title\": \"Test project\", \"directory_name\": \"\", \"directory_name_type\": \"\", \"ngi_project_name\": \"ngi-project-name\", \"abstract\": \"\", \"webpage\": \"\", \"affiliation\": \"Affiliate\", \"classification1\": \"\", \"classification2\": \"\", \"classification3\": \"\", \"managed_in_supr\": true, \"api_opaque_data\": \"\", \"ngi_sensitive_data\": true, \"ngi_ready\": false, \"ngi_delivery_status\": \"\", \"continuation_name\": \"\", \"start_date\": \"2022-09-19\", \"end_date\": \"2022-12-31\", \"pi\": {\"id\": 123, \"first_name\": \"Name\", \"last_name\": \"Lastname\", \"email\": \"some.other.user@nbis.se\"}, \"members\": [{\"id\": 175, \"first_name\": \"Name\", \"last_name\": \"Lastname\", \"email\": \"some.user@nbis.se\"}], \"links_outgoing\": [], \"links_incoming\": [], \"resourceprojects\": [{\"id\": 123, \"allocated\": 1000, \"resource\": {\"id\": 123, \"name\": \"Grus\", \"capacity_unit\": \"GiB\", \"capacity_unit_2\": \"\", \"centre\": {\"id\": 123, \"name\": \"UPPMAX\"}}, \"decommissioning_state\": \"N/A\", \"allocations\": [{\"id\": 123, \"start_date\": \"2022-09-19\", \"end_date\": \"2022-12-31\", \"allocated\": 1000}]}], \"modified\": \"2022-09-19 14:50:39\"}], \"began\": \"2023-02-06 13:04:31\"}")
	}))
	defer supr.Close()

	requestBody := &tokenRequest{
		ProjectID: "someproject",
		SwamID:    "some.user@nbis.se",
	}

	confData := `global:
  crypt4ghKey: ` + suite.Crypt4ghKeyPath + `
  egaUsername: "some-user"
  egaPassword: "some-pass"
  egaURL: "` + ega.URL + `"
  expirationDays: 14
  iss: "https://some.url"
  jwtKey: "` + suite.PrivateKeyPath + `"
  suprUsername: "some-user"
  suprPassword: "some-pass"
  suprURL: "` + supr.URL + `"
  s3url: "some.s3.url"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
`
	configName := "config.yaml"
	err := os.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	err = verifyProjectAccount(requestBody.SwamID, requestBody.ProjectID)
	assert.Equal(suite.T(), fmt.Errorf("email is different than PI in requested project"), err)

}
