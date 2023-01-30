package helpers

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	b64 "encoding/base64"

	log "github.com/sirupsen/logrus"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/viper"
)

// Config holds the configuration of the service
var Config Conf

// Conf describes the configuration of the service
type Conf struct {
	Crypt4ghKeyPath string
	Crypt4ghKey     string
	EgaUser         string
	ExpirationDays  int
	Iss             string
	JwtKeyPath      string
	JwtParsedKey    *ecdsa.PrivateKey
	S3URL           string
	Username        string
	Password        string
}

// NewConf reads the configuration from the config.yaml file
func NewConf(conf *Conf) (err error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetConfigType("yaml")
	if viper.IsSet("configPath") {
		configPath := viper.GetString("configPath")
		splitPath := strings.Split(strings.TrimLeft(configPath, "/"), "/")
		viper.AddConfigPath(path.Join(splitPath...))
	}

	if viper.IsSet("configFile") {
		viper.SetConfigFile(viper.GetString("configFile"))
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("No config file found, using ENVs only")
		} else {
			return err
		}
	}

	requiredConfVars := []string{
		"global.iss", "global.crypt4ghKey", "global.uppmaxUsername", "global.uppmaxPassword", "global.s3url", "global.egaUser", "global.jwtKey",
	}

	for _, s := range requiredConfVars {
		if !viper.IsSet(s) || viper.GetString(s) == "" {
			return fmt.Errorf("Required configuration field %s not set", s)
		}
	}

	conf.Iss = viper.GetString("global.iss")
	conf.JwtKeyPath = viper.GetString("global.jwtKey")
	conf.Username = viper.GetString("global.uppmaxUsername")
	conf.Password = viper.GetString("global.uppmaxPassword")
	conf.S3URL = viper.GetString("global.s3url")
	conf.EgaUser = viper.GetString("global.egaUser")
	conf.Crypt4ghKeyPath = viper.GetString("global.crypt4ghKey")

	if !viper.IsSet("global.expirationDays") {
		conf.ExpirationDays = 14
	} else {
		conf.ExpirationDays = viper.GetInt("global.expirationDays")
	}
	conf.JwtParsedKey, err = parsePrivateECKey(conf.JwtKeyPath)
	if err != nil {
		return fmt.Errorf("Could not parse ec key")
	}
	// Parse crypt4gh key and store it as base64 encoded
	keyBytes, err := os.ReadFile(conf.Crypt4ghKeyPath)
	if err != nil {
		return fmt.Errorf("Could not parse crypt4gh public key")
	}
	conf.Crypt4ghKey = b64.StdEncoding.EncodeToString([]byte(keyBytes))

	return nil
}

type errorStruct struct {
	ErrorStruct struct {
		Message string `json:"message"`
	} `json:"error"`
}

// CreateErrorResponse returns a JSON structure containing the error passed in the function
func CreateErrorResponse(errorMessage string) (errorBytes []byte) {
	currentError := errorStruct{}
	currentError.ErrorStruct.Message = errorMessage
	errorBytes, _ = json.Marshal(currentError)

	return errorBytes
}

// BasicAuth checks if the used credentials match the defined ones and
// returns unauthorised if that's not the case
func BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(Config.Username))
			expectedPasswordHash := sha256.Sum256([]byte(Config.Password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)

				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// ParsePrivateECKey reads and parses the EC private key
func parsePrivateECKey(keyPath string) (*ecdsa.PrivateKey, error) {

	prKey, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	prKeyParsed, err := jwt.ParseECPrivateKeyFromPEM(prKey)
	if err != nil {
		return nil, err
	}

	return prKeyParsed, nil
}
