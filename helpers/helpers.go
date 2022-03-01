package helpers

import "encoding/json"

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
