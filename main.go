package main

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/cli/go-gh"
)

func _main() error {
	// rootCmd := &cobra.Command{
	// 	Use:   "revoke <subcommand> [flags]",
	// 	Short: "gh revoke",
	// }
	// get org flag value
	org := ""
	var err = survey.AskOne(&survey.Input{
		Message: "Enter the name of the org you want to revoke access to:",
	}, &org)
	if err != nil {
		return err
	} else if org == "" {
		return fmt.Errorf("org cannot be empty")
	}
	token := ""
	lastEight := ""
	err = survey.AskOne(&survey.Password{
		Message: "Enter the github personal access token to be revoked:",
	}, &token)
	if err != nil {
		return err
	} else if token == "" {
		return fmt.Errorf("token cannot be empty")
	} else if len(token) != 40 {
		return fmt.Errorf("token must be 40 characters long")
	} else if len(token) == 8 {
		lastEight = token
	} else {
		lastEight = token[len(token)-8:]
	}

	login, auths, err := getAuthLogin(org)
	if err != nil {
		return err
	}
	isAdmin, err := checkIfUserIsOrgAdmin(org, login)
	if err != nil {
		return err
	} else if !isAdmin {
		return fmt.Errorf("You are not an admin of the org.")
	}

	// check if token is in auths
	found := false
	authID := int64(0)
	revokedUser := ""
	for _, auth := range auths {
		if auth.TokenLastEight == lastEight {
			found = true
			authID = auth.CredentialID
			revokedUser = auth.Login
		}
	}
	if !found {
		return fmt.Errorf("Token is not in the list of authorizations for org: " + org)
	} else {
		fmt.Println("\u2713 Token found for user: " + revokedUser)
		confirm := false
		err = survey.AskOne(&survey.Confirm{
			Message: "Are you sure you want to revoke access for user: " + revokedUser + "?",
		}, &confirm)
		if confirm == false {
			return fmt.Errorf("revocation cancelled")
		}
		revokeAuth(org, authID)
		fmt.Println("\u2713 Token revoked for user: " + revokedUser)
	}
	return nil
}

type MembershipResponse struct {
	URL   string `json:"url"`
	State string `json:"state"`
	Role  string `json:"role"`
	User  struct {
		Login     string `json:"login"`
		ID        int64  `json:"id"`
		Type      string `json:"type"`
		SiteAdmin bool   `json:"site_admin"`
	} `json:"user"`
	Organization struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"organization"`
}

func checkIfUserIsOrgAdmin(org string, login string) (bool, error) {
	client, err := gh.RESTClient(nil)
	if err != nil {
		return false, fmt.Errorf("failed to create client: %w", err)
	}
	response := MembershipResponse{}
	err = client.Get("orgs/"+org+"/memberships/"+login+"", &response)
	if err != nil {
		return false, fmt.Errorf("failed to get admin status: %w", err)
	}
	// check SiteAdmin is true where org is the same as the org we are checking
	isAdmin := false
	if response.Organization.Login == org && response.Role == "admin" {
		isAdmin = true
	}
	return isAdmin, nil
}
func getAuthLogin(org string) (string, []AuthResponse, error) {
	client, err := gh.RESTClient(nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create client: %w", err)
	}
	response := struct{ Login string }{}
	err = client.Get("user", &response)
	if err != nil {
		return "", nil, err
	}
	currentUsername := response.Login
	auths, err := listAuths(org)
	if err != nil {
		return "", nil, err
	}
	return currentUsername, auths, nil
}

type AuthResponse struct {
	Login                  string `json:"login"`
	CredentialID           int64  `json:"credential_id"`
	CredentialType         string `json:"credential_type"`
	AuthorizedCredentialID int64  `json:"authorized_credential_id"`
	TokenLastEight         string `json:"token_last_eight"`
}

func listAuths(org string) ([]AuthResponse, error) {
	client, err := gh.RESTClient(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	response := []AuthResponse{}

	err = client.Get("orgs/"+org+"/credential-authorizations", &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get auths: %w", err)
	}

	return response, nil
}

func revokeAuth(org string, authID int64) error {
	client, err := gh.RESTClient(nil)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	err = client.Delete("orgs/"+org+"/credential-authorizations/"+string(authID), nil)
	if err != nil {
		return fmt.Errorf("failed to revoke auth: %w", err)
	}
	return nil
}

func main() {
	if err := _main(); err != nil {
		fmt.Fprintf(os.Stderr, "X %s", err.Error())
	}
}
