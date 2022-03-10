package helpers

import (
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (suite *TestSuite) SetupTest() {

}

func (suite *TestSuite) TestCreateErrorResponse() {

	errorMessage := "some error"
	errorBytes := CreateErrorResponse(errorMessage)

	assert.Equal(suite.T(), errorBytes, []byte("{\"error\":{\"message\":\"some error\"}}"))
}

func (suite *TestSuite) TestNewConf() {
	confData := `global:
  iss: "https://some.url"
  pathToKey: "../dev_utils/dummy.ec.nbis.se"
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

	err = NewConf(&Config)
	assert.NoError(suite.T(), err)

	defer os.Remove(configName)
}

func (suite *TestSuite) TestNewConfMissingValue() {
	confData := `global:
  pathToKey: "../dev_utils/dummy.ec.nbis.se"
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

	err = NewConf(&Config)
	assert.EqualError(suite.T(), err, "Required configuration field global.iss not set")

	defer os.Remove(configName)
}

func (suite *TestSuite) TestNewConfMissingKey() {
	confData := `global:
  iss: "https://some.url"
  pathToKey: "some/path"
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

	err = NewConf(&Config)
	assert.EqualError(suite.T(), err, "Could not parse ec key")

	defer os.Remove(configName)
}

func (suite *TestSuite) TestParsePrivateECKey() {

	keyPath := "../dev_utils/dummy.ec.nbis.se"
	_, err := parsePrivateECKey(keyPath)
	assert.NoError(suite.T(), err)

	keyPath = "some/path"
	_, err = parsePrivateECKey(keyPath)
	assert.EqualError(suite.T(), err, "open some/path: no such file or directory")
}
