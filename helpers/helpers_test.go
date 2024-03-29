package helpers

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/NBISweden/sda-uppmax-integration/testhelpers"
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

func (suite *TestSuite) TestCreateErrorResponse() {

	errorMessage := "some error"
	errorBytes := CreateErrorResponse(errorMessage)

	assert.Equal(suite.T(), errorBytes, []byte("{\"error\":{\"message\":\"some error\"}}"))
}

func (suite *TestSuite) TestNewConf() {
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

	err = NewConf(&Config)
	assert.NoError(suite.T(), err)

	defer os.Remove(configName)
}

func (suite *TestSuite) TestNewConfMissingValue() {
	confData := `global:
  jwtKey: "` + suite.PrivateKeyPath + `"
  uppmaxUsername: "user"
  uppmaxPassword: "password"
  s3url: "some.s3.url"
  expirationDays: 14
  egaUser: "some-user"
  crypt4ghKey: "` + suite.Crypt4ghKeyPath + `"
`

	configName := "config.yaml"
	err := os.WriteFile(configName, []byte(confData), 0600)
	if err != nil {
		log.Printf("failed to write temp config file, %v", err)
	}

	err = NewConf(&Config)
	assert.EqualError(suite.T(), err, "required configuration field global.iss not set")

	defer os.Remove(configName)
}

func (suite *TestSuite) TestNewConfMissingKey() {
	confData := `global:
  crypt4ghKey: "` + suite.Crypt4ghKeyPath + `"
  egaUsername: "some-user"
  egaPassword: "some-pass"
  egaURL: "http://ega.dev"
  expirationDays: 14
  iss: "https://some.url"
  jwtKey: "some/path"
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

	err = NewConf(&Config)
	assert.EqualError(suite.T(), err, "could not parse ec key: open some/path: no such file or directory")

	defer os.Remove(configName)
}

func (suite *TestSuite) TestParsePrivateECKey() {

	_, err := parsePrivateECKey(suite.PrivateKeyPath)
	assert.NoError(suite.T(), err)

	privateKeyPath := "some/path"
	_, err = parsePrivateECKey(privateKeyPath)
	assert.EqualError(suite.T(), err, "open some/path: no such file or directory")

	defer os.Remove(privateKeyPath)
}
