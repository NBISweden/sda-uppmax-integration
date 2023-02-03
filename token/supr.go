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

type SuprResponse struct {
	Matches []Match `json:"matches"`
	Began   string  `json:"began"`
}

type Match struct {
	ID                int               `json:"id"`
	Type              string            `json:"type"`
	Name              string            `json:"name"`
	Title             string            `json:"title"`
	DirectoryName     string            `json:"directory_name"`
	DirectoryNameType string            `json:"directory_name_type"`
	NgiProjectName    string            `json:"ngi_project_name"`
	Abstract          string            `json:"abstract"`
	Webpage           string            `json:"webpage"`
	Affiliation       string            `json:"affiliation"`
	Classification1   string            `json:"classification1"`
	Classification2   string            `json:"classification2"`
	Classification3   string            `json:"classification3"`
	ManagedInSupr     bool              `json:"managed_in_supr"`
	APIOpaqueData     string            `json:"api_opaque_data"`
	NgiSensitiveData  bool              `json:"ngi_sensitive_data"`
	NgiReady          bool              `json:"ngi_ready"`
	NgiDeliveryStatus string            `json:"ngi_delivery_status"`
	ContinuationName  string            `json:"continuation_name"`
	StartDate         string            `json:"start_date"`
	EndDate           string            `json:"end_date"`
	Pi                Pi                `json:"pi"`
	Members           []Member          `json:"members"`
	LinksOutgoing     []interface{}     `json:"links_outgoing"`
	LinksIncoming     []interface{}     `json:"links_incoming"`
	Resourceprojects  []ResourceProject `json:"resourceprojects"`
	Modified          string            `json:"modified"`
}

type Pi struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

type Member struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

type ResourceProject struct {
	ID                   int          `json:"id"`
	Allocated            int          `json:"allocated"`
	Resource             Resource     `json:"resource"`
	DecommissioningState string       `json:"decommissioning_state"`
	Allocations          []Allocation `json:"allocations"`
}

type SuprHeader struct {
	APIVersion       string `json:"apiVersion"`
	Code             int    `json:"code"`
	Service          string `json:"service"`
	DeveloperMessage string `json:"developerMessage"`
	UserMessage      string `json:"userMessage"`
	ErrorCode        int    `json:"errorCode"`
	DocLink          string `json:"docLink"`
}

type SuprUserResult struct {
	Username     string `json:"username"`
	SSHPublicKey string `json:"sshPublicKey"`
	PasswordHash string `json:"passwordHash"`
	UID          int    `json:"uid"`
	Gecos        string `json:"gecos"`
}

type Resource struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	CapacityUnit  string `json:"capacity_unit"`
	CapacityUnit2 string `json:"capacity_unit_2"`
	Centre        Center `json:"centre"`
}

type Allocation struct {
	ID        int    `json:"id"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	Allocated int    `json:"allocated"`
}

type Center struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// verifyProjectAccount checks that the given `email` is actually
// the PI of the given `project_id` and returns error otherwise
func verifyProjectAccount(username string, projectID string) (err error) {

	suprUser := helpers.Config.SuprUsername
	suprPass := helpers.Config.SuprPassword
	suprURL := helpers.Config.SuprURL

	url := fmt.Sprintf("%v?name=%v", suprURL, projectID)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {

		return err
	}
	req.SetBasicAuth(suprUser, suprPass)
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

		return fmt.Errorf("got %v from SUPR", message)
	}

	var response SuprResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {

		return err
	}

	defer resp.Body.Close()
	log.Debugf("reply: %v", response)

	if response.Matches[0].Pi.Email != username {
		log.Infof("Email %v does not exist for SUPR project %v", username, projectID)

		return fmt.Errorf("email is different than PI in requested project")
	}

	return nil
}
