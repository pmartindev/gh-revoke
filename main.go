package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	gh "github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/api"
)

const (
	fullTokenLength      = 40
	tokenLastEightLength = 8
)

var (
	errCancelled          = errors.New("operation cancelled")
	errRevocationCanceled = errors.New("revocation cancelled")
	surveyAskOne          = survey.AskOne
	newRESTClient         = func() (api.RESTClient, error) { return gh.RESTClient(nil) }
)

func _main() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	org, err := promptForOrg(ctx)
	if err != nil {
		return err
	}

	token, err := promptForToken(ctx)
	if err != nil {
		return err
	}
	lastEight := tokenLastEight(token)

	for {
		login, auths, err := getAuthLogin(ctx, org)
		if err != nil {
			if shouldRepromptOrg(err) {
				fmt.Fprintf(os.Stderr, "! %s\n", err)
				org, err = promptForOrg(ctx)
				if err != nil {
					return err
				}
				continue
			}
			return err
		}

		isAdmin, err := checkIfUserIsOrgAdmin(ctx, org, login)
		if err != nil {
			return err
		}
		if !isAdmin {
			fmt.Fprintf(os.Stderr, "! %s is not an admin of %q. Try another organization.\n", login, org)
			org, err = promptForOrg(ctx)
			if err != nil {
				return err
			}
			continue
		}

		refreshOrg := false
		for {
			auth, found := findAuthorization(auths, lastEight)
			if !found {
				fmt.Fprintf(os.Stderr, "! No credential authorization ending in %s was found for %q.\n", lastEight, org)
				token, err = promptForToken(ctx)
				if err != nil {
					return err
				}
				lastEight = tokenLastEight(token)

				auths, err = listAuths(ctx, org)
				if err != nil {
					if shouldRepromptOrg(err) {
						fmt.Fprintf(os.Stderr, "! %s\n", err)
						org, err = promptForOrg(ctx)
						if err != nil {
							return err
						}
						refreshOrg = true
						break
					}
					return err
				}
				continue
			}

			fmt.Printf("✓ Token found for user: %s\n", auth.Login)

			confirm, err := promptForConfirmation(ctx, auth.Login)
			if err != nil {
				return err
			}
			if !confirm {
				return errRevocationCanceled
			}

			if err := revokeAuth(ctx, org, auth.CredentialID); err != nil {
				return err
			}

			fmt.Printf("✓ Token revoked for user: %s\n", auth.Login)
			return nil
		}
		if refreshOrg {
			continue
		}
	}
}

func promptForOrg(ctx context.Context) (string, error) {
	for {
		if err := contextErr(ctx); err != nil {
			return "", err
		}

		org := ""
		err := surveyAskOne(&survey.Input{
			Message: "Enter the name of the org you want to revoke access to:",
		}, &org)
		if err != nil {
			return "", normalizePromptError(err)
		}

		org = strings.TrimSpace(org)
		if org == "" {
			fmt.Fprintln(os.Stderr, "! Organization name cannot be empty.")
			continue
		}

		return org, nil
	}
}

func promptForToken(ctx context.Context) (string, error) {
	for {
		if err := contextErr(ctx); err != nil {
			return "", err
		}

		token := ""
		err := surveyAskOne(&survey.Password{
			Message: "Enter the GitHub personal access token to be revoked:",
		}, &token)
		if err != nil {
			return "", normalizePromptError(err)
		}

		token = strings.TrimSpace(token)
		switch {
		case token == "":
			fmt.Fprintln(os.Stderr, "! Token cannot be empty.")
		case len(token) == tokenLastEightLength || len(token) == fullTokenLength:
			return token, nil
		default:
			fmt.Fprintf(os.Stderr, "! Enter either the full %d-character PAT or the last %d characters shown in GitHub.\n", fullTokenLength, tokenLastEightLength)
		}
	}
}

func promptForConfirmation(ctx context.Context, login string) (bool, error) {
	if err := contextErr(ctx); err != nil {
		return false, err
	}

	confirm := false
	err := surveyAskOne(&survey.Confirm{
		Message: "Are you sure you want to revoke access for user: " + login + "?",
	}, &confirm)
	if err != nil {
		return false, normalizePromptError(err)
	}

	return confirm, nil
}

func normalizePromptError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, terminal.InterruptErr) || errors.Is(err, context.Canceled) {
		return errCancelled
	}
	return err
}

func contextErr(ctx context.Context) error {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	return errCancelled
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

func checkIfUserIsOrgAdmin(ctx context.Context, org, login string) (bool, error) {
	client, err := restClient()
	if err != nil {
		return false, err
	}
	return checkIfUserIsOrgAdminWithClient(ctx, client, org, login)
}

func checkIfUserIsOrgAdminWithClient(ctx context.Context, client api.RESTClient, org, login string) (bool, error) {
	response := MembershipResponse{}
	err := client.DoWithContext(ctx, http.MethodGet, fmt.Sprintf("orgs/%s/memberships/%s", org, login), nil, &response)
	if err != nil {
		var httpErr api.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, formatRequestError(fmt.Sprintf("verify admin access for %q", org), err)
	}

	return strings.EqualFold(response.Organization.Login, org) && response.Role == "admin", nil
}

func getAuthLogin(ctx context.Context, org string) (string, []AuthResponse, error) {
	client, err := restClient()
	if err != nil {
		return "", nil, err
	}
	return getAuthLoginWithClient(ctx, client, org)
}

func getAuthLoginWithClient(ctx context.Context, client api.RESTClient, org string) (string, []AuthResponse, error) {
	response := struct {
		Login string `json:"login"`
	}{}
	if err := client.DoWithContext(ctx, http.MethodGet, "user", nil, &response); err != nil {
		return "", nil, formatRequestError("read the authenticated GitHub user", err)
	}
	if strings.TrimSpace(response.Login) == "" {
		return "", nil, fmt.Errorf("GitHub did not return the authenticated username")
	}

	auths, err := listAuthsWithClient(ctx, client, org)
	if err != nil {
		return "", nil, err
	}

	return response.Login, auths, nil
}

type AuthResponse struct {
	Login                  string `json:"login"`
	CredentialID           int64  `json:"credential_id"`
	CredentialType         string `json:"credential_type"`
	AuthorizedCredentialID int64  `json:"authorized_credential_id"`
	TokenLastEight         string `json:"token_last_eight"`
}

func listAuths(ctx context.Context, org string) ([]AuthResponse, error) {
	client, err := restClient()
	if err != nil {
		return nil, err
	}
	return listAuthsWithClient(ctx, client, org)
}

func listAuthsWithClient(ctx context.Context, client api.RESTClient, org string) ([]AuthResponse, error) {
	response := []AuthResponse{}
	err := client.DoWithContext(ctx, http.MethodGet, fmt.Sprintf("orgs/%s/credential-authorizations", org), nil, &response)
	if err != nil {
		var httpErr api.HTTPError
		if errors.As(err, &httpErr) {
			switch httpErr.StatusCode {
			case http.StatusNotFound:
				return nil, invalidOrgError{org: org}
			case http.StatusForbidden:
				return nil, adminAccessError{org: org}
			}
		}
		return nil, formatRequestError(fmt.Sprintf("list SSO credential authorizations for %q", org), err)
	}

	return response, nil
}

func revokeAuth(ctx context.Context, org string, authID int64) error {
	client, err := restClient()
	if err != nil {
		return err
	}
	return revokeAuthWithClient(ctx, client, org, authID)
}

func revokeAuthWithClient(ctx context.Context, client api.RESTClient, org string, authID int64) error {
	path := fmt.Sprintf("orgs/%s/credential-authorizations/%s", org, strconv.FormatInt(authID, 10))
	if err := client.DoWithContext(ctx, http.MethodDelete, path, nil, nil); err != nil {
		var httpErr api.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return fmt.Errorf("credential authorization %d was not found in %q. It may have already been revoked", authID, org)
		}
		return formatRequestError(fmt.Sprintf("revoke SSO access in %q", org), err)
	}
	return nil
}

func restClient() (api.RESTClient, error) {
	client, err := newRESTClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub API client: %w", err)
	}
	return client, nil
}

func formatRequestError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, terminal.InterruptErr) || errors.Is(err, errCancelled) {
		return errCancelled
	}

	var httpErr api.HTTPError
	if errors.As(err, &httpErr) {
		message := strings.TrimSpace(strings.ReplaceAll(httpErr.Message, "\n", ": "))
		switch httpErr.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("GitHub authentication failed while trying to %s. Run `gh auth status` and try again", action)
		case http.StatusForbidden:
			if message != "" {
				return fmt.Errorf("GitHub denied permission to %s: %s", action, message)
			}
			return fmt.Errorf("GitHub denied permission to %s. Ensure your gh account has the required organization admin access", action)
		case http.StatusNotFound:
			if message != "" {
				return fmt.Errorf("GitHub could not %s: %s", action, message)
			}
			return fmt.Errorf("GitHub could not %s because the resource was not found", action)
		default:
			if message != "" {
				return fmt.Errorf("GitHub API error while trying to %s: %s", action, message)
			}
			return fmt.Errorf("GitHub API error while trying to %s: HTTP %d", action, httpErr.StatusCode)
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return fmt.Errorf("network timeout while trying to %s. Check your connection and try again", action)
		}
		return fmt.Errorf("network error while trying to %s. Check your connection and try again: %v", action, err)
	}

	return fmt.Errorf("failed to %s: %w", action, err)
}

type invalidOrgError struct {
	org string
}

func (e invalidOrgError) Error() string {
	return fmt.Sprintf("could not access organization %q. Check the organization name and ensure your gh account can manage its SSO authorizations", e.org)
}

type adminAccessError struct {
	org string
}

func (e adminAccessError) Error() string {
	return fmt.Sprintf("your gh account does not appear to be an admin of %q. Try another organization or authenticate with an org admin account", e.org)
}

func shouldRepromptOrg(err error) bool {
	var invalidOrg invalidOrgError
	if errors.As(err, &invalidOrg) {
		return true
	}
	var adminAccess adminAccessError
	return errors.As(err, &adminAccess)
}

func tokenLastEight(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= tokenLastEightLength {
		return token
	}
	return token[len(token)-tokenLastEightLength:]
}

func findAuthorization(auths []AuthResponse, lastEight string) (AuthResponse, bool) {
	for _, auth := range auths {
		if auth.TokenLastEight == lastEight {
			return auth, true
		}
	}
	return AuthResponse{}, false
}

func main() {
	if err := _main(); err != nil {
		if errors.Is(err, errCancelled) {
			fmt.Fprintln(os.Stderr, "Cancelled.")
			os.Exit(130)
		}
		fmt.Fprintf(os.Stderr, "X %s\n", err.Error())
		os.Exit(1)
	}
}
