package token

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NBISweden/sda-uppmax-integration/helpers"
	log "github.com/sirupsen/logrus"
)

type EgaHeader struct {
	APIVersion       string `json:"apiVersion"`
	Code             int    `json:"code"`
	Service          string `json:"service"`
	DeveloperMessage string `json:"developerMessage"`
	UserMessage      string `json:"userMessage"`
	ErrorCode        int    `json:"errorCode"`
	DocLink          string `json:"docLink"`
}

type EgaUserResult struct {
	Username     string `json:"username"`
	SSHPublicKey string `json:"sshPublicKey"`
	PasswordHash string `json:"passwordHash"`
	UID          int    `json:"uid"`
	Gecos        string `json:"gecos"`
}

type EgaResponse struct {
	NumTotalResults int             `json:"numTotalResults"`
	ResultType      string          `json:"resultType"`
	Result          []EgaUserResult `json:"result"`
}

type EgaReply struct {
	Header   EgaHeader   `json:"header"`
	Response EgaResponse `json:"response"`
}

// verifyEGABoxAccount checks that a given `username` is a valid EGA account, and
// returns error if the user does not exist.
func verifyEGABoxAccount(username string) (err error) {

	egaUser := helpers.Config.EgaUsername
	egaPass := helpers.Config.EgaPassword
	egaURL := helpers.Config.EgaURL

	url := fmt.Sprintf("%v/%v?idType=username", egaURL, username)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {

		return err
	}
	req.SetBasicAuth(egaUser, egaPass)
	resp, err := client.Do(req)
	if err != nil {

		return err
	}

	if resp.StatusCode != 200 {

		message, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		return fmt.Errorf("got %v from EGA", message)
	}

	var reply EgaReply
	err = json.NewDecoder(resp.Body).Decode(&reply)
	if err != nil {

		return err
	}

	defer resp.Body.Close()
	log.Debugf("reply: %v", reply)
	if len(reply.Response.Result) == 0 {

		return nil
	}

	return nil
}
