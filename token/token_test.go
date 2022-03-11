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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	PrivateKeyPath string
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {
	suite.PrivateKeyPath, _ = testHelpers.CreateECkeys(os.TempDir())
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
`
	configName := "config.yaml"
	err := ioutil.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = helpers.NewConf(&helpers.Config)
	assert.NoError(suite.T(), err)

	_, err = createECToken(helpers.Config.ParsedKey, "username")

	assert.NoError(suite.T(), err)

	s3config, _, err := createS3Config("someuser")

	assert.NoError(suite.T(), err)

	// The S3 config base64 encode - Need to decode before running assert
	s3configDec, _ := b64.StdEncoding.DecodeString(s3config)
	assert.Contains(suite.T(), string(s3configDec), "someuser")

	defer os.Remove(configName)
}
