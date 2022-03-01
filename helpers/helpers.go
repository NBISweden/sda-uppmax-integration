package helpers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

type errorStruct struct {
	ErrorStruct struct {
		Message string `json:"message"`
	} `json:"error"`
}

func CreateErrorResponse(errorMessage string) (errorBytes []byte) {
	currentError := errorStruct{}
	currentError.ErrorStruct.Message = errorMessage
	errorBytes, _ = json.Marshal(currentError)

	return errorBytes
}

var Username = "uppmax"
var Password = "uppmax"

func BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(Username))
			expectedPasswordHash := sha256.Sum256([]byte(Password))

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
