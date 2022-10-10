package token

import (
	b64 "encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	"github.com/NBISweden/sda-uppmax-integration/testHelpers"
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
	suite.TempDir, _ = ioutil.TempDir(os.TempDir(), "keys-")
	suite.PrivateKeyPath, _ = testHelpers.CreateECkeys(suite.TempDir)

	// Create random public crypt4gh key
	cryptKey := "-----BEGIN CRYPT4GH PUBLIC KEY-----\nvSome+asd/apublicKey\n-----END CRYPT4GH PUBLIC KEY-----"
	crypt4ghFile, _ := ioutil.TempFile(suite.TempDir, "rsakey-")
	_, err := crypt4ghFile.Write([]byte(cryptKey))
	if err != nil {
		log.Fatal(err)
	}
	suite.Crypt4ghKeyPath = crypt4ghFile.Name()

	_ = ioutil.WriteFile(suite.Crypt4ghKeyPath, []byte(cryptKey), 0600)

}

func (suite *TestSuite) TestNewConf() {
	expectedToken := tokenRequest{
		Swamid:    "<swamid>",
		ProjectID: "<projectid>",
	}

	r := ioutil.NopCloser(strings.NewReader(`{
		"swamid": "<swamid>",
		"projectid": "<projectid>"
	}`))

	tokenRequest, err := readRequestBody(r)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedToken, tokenRequest)

	r = ioutil.NopCloser(strings.NewReader(`{
		"swami": "<swamid>",
		"projectid": "<projectid>"
	`))

	_, err = readRequestBody(r)

	assert.EqualError(suite.T(), err, "Error unmarshaling data")

	r = ioutil.NopCloser(strings.NewReader(`{
		"swami": "<swamid>",
		"projectid": "<projectid>"
	}`))

	_, err = readRequestBody(r)

	assert.EqualError(suite.T(), err, "Incomplete incoming data")
}

func (suite *TestSuite) TestCreateECToken() {

	confData := `global:
  iss: "https://some.url"
  pathToKey: "` + suite.PrivateKeyPath + `"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
  s3url: "some.s3.url"
  expirationDays: 14
  egaUser: "some-user"
  crypt4ghKeyPath: "` + suite.Crypt4ghKeyPath + `"
`
	configName := "config.yaml"
	err := ioutil.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	tokenString, err := createECToken(helpers.Config.ParsedKey, helpers.Config.EgaUser)
	assert.NoError(suite.T(), err)

	// Parse token to make sure it contains the correct information
	token, _ := jwt.Parse(tokenString, func(tokenElixir *jwt.Token) (interface{}, error) { return nil, nil })
	claims, _ := token.Claims.(jwt.MapClaims)

	// Check that token includes the correct information
	assert.Equal(suite.T(), helpers.Config.Username, claims["pilot"])
	assert.Equal(suite.T(), helpers.Config.Iss, claims["iss"])
	assert.Equal(suite.T(), helpers.Config.EgaUser, claims["sub"])

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
		Swamid:    "someswam",
	}

	confData := `global:
  iss: "https://some.url"
  pathToKey: "` + suite.PrivateKeyPath + `"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
  s3url: "some.s3.url"
  expirationDays: 14
  egaUser: "some-user"
  crypt4ghKeyPath: "` + suite.Crypt4ghKeyPath + `"
`
	configName := "config.yaml"
	err := ioutil.WriteFile(configName, []byte(confData), 0600)
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
	assert.Equal(suite.T(), requestBody.Swamid, responseBody.Swamid)

	defer os.Remove(configName)
}
