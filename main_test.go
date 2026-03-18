package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/cli/go-gh/pkg/api"
)

type mockRESTClient struct {
	doWithContext func(ctx context.Context, method, path string, body io.Reader, response interface{}) error
}

func (m mockRESTClient) Do(method string, path string, body io.Reader, response interface{}) error {
	return m.DoWithContext(context.Background(), method, path, body, response)
}

func (m mockRESTClient) DoWithContext(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
	if m.doWithContext != nil {
		return m.doWithContext(ctx, method, path, body, response)
	}
	return fmt.Errorf("unexpected request: %s %s", method, path)
}

func (m mockRESTClient) Delete(path string, response interface{}) error {
	return m.DoWithContext(context.Background(), http.MethodDelete, path, nil, response)
}

func (m mockRESTClient) Get(path string, response interface{}) error {
	return m.DoWithContext(context.Background(), http.MethodGet, path, nil, response)
}

func (m mockRESTClient) Patch(path string, body io.Reader, response interface{}) error {
	return m.DoWithContext(context.Background(), http.MethodPatch, path, body, response)
}

func (m mockRESTClient) Post(path string, body io.Reader, response interface{}) error {
	return m.DoWithContext(context.Background(), http.MethodPost, path, body, response)
}

func (m mockRESTClient) Put(path string, body io.Reader, response interface{}) error {
	return m.DoWithContext(context.Background(), http.MethodPut, path, body, response)
}

func (m mockRESTClient) Request(method string, path string, body io.Reader) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected request: %s %s", method, path)
}

func (m mockRESTClient) RequestWithContext(ctx context.Context, method string, path string, body io.Reader) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected request: %s %s", method, path)
}

func useMockRESTClient(t *testing.T, client api.RESTClient) {
	t.Helper()
	previous := newRESTClient
	newRESTClient = func() (api.RESTClient, error) {
		return client, nil
	}
	t.Cleanup(func() {
		newRESTClient = previous
	})
}

func useMockSurveyAskOne(t *testing.T, mock func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error) {
	t.Helper()
	previous := surveyAskOne
	surveyAskOne = mock
	t.Cleanup(func() {
		surveyAskOne = previous
	})
}

func TestTokenLastEight(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{name: "full token", token: "12345678901234567890123456789012abcdefgh", want: "abcdefgh"},
		{name: "last eight only", token: "abcd1234", want: "abcd1234"},
		{name: "trims spaces", token: "  abcd1234  ", want: "abcd1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tokenLastEight(tt.token); got != tt.want {
				t.Fatalf("tokenLastEight() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindAllAuthorizations(t *testing.T) {
	auths := []AuthResponse{
		{Login: "octocat", CredentialID: 9, TokenLastEight: "deadbeef"},
		{Login: "monalisa", CredentialID: 10, TokenLastEight: "deadbeef"},
		{Login: "hubot", CredentialID: 11, TokenLastEight: "cafebabe"},
	}

	t.Run("single match", func(t *testing.T) {
		matches := findAllAuthorizations(auths, "cafebabe")
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if matches[0].Login != "hubot" {
			t.Fatalf("expected hubot, got %s", matches[0].Login)
		}
	})

	t.Run("multiple matches", func(t *testing.T) {
		matches := findAllAuthorizations(auths, "deadbeef")
		if len(matches) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(matches))
		}
		if matches[0].Login != "octocat" || matches[1].Login != "monalisa" {
			t.Fatalf("unexpected matches: %+v", matches)
		}
	})

	t.Run("no match", func(t *testing.T) {
		matches := findAllAuthorizations(auths, "notfound")
		if len(matches) != 0 {
			t.Fatalf("expected 0 matches, got %d", len(matches))
		}
	})
}

func TestGetAuthLoginSuccess(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		switch path {
		case "user":
			resp := response.(*struct {
				Login string `json:"login"`
			})
			resp.Login = "maintainer"
			return nil
		case "orgs/acme/credential-authorizations":
			resp := response.(*[]AuthResponse)
			*resp = []AuthResponse{{Login: "octocat", CredentialID: 42, TokenLastEight: "deadbeef"}}
			return nil
		default:
			return fmt.Errorf("unexpected path: %s", path)
		}
	}})

	login, auths, err := getAuthLogin(context.Background(), "acme")
	if err != nil {
		t.Fatalf("getAuthLogin() error = %v", err)
	}
	if login != "maintainer" {
		t.Fatalf("getAuthLogin() login = %q, want %q", login, "maintainer")
	}
	if len(auths) != 1 || auths[0].CredentialID != 42 {
		t.Fatalf("getAuthLogin() auths = %+v, want one matching authorization", auths)
	}
}

func TestGetAuthLoginInvalidOrg(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		switch path {
		case "user":
			resp := response.(*struct {
				Login string `json:"login"`
			})
			resp.Login = "maintainer"
			return nil
		case "orgs/missing/credential-authorizations":
			return api.HTTPError{StatusCode: http.StatusNotFound, Message: "Not Found"}
		default:
			return fmt.Errorf("unexpected path: %s", path)
		}
	}})

	_, _, err := getAuthLogin(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected getAuthLogin() to return an error")
	}
	if !shouldRepromptOrg(err) {
		t.Fatalf("expected invalid org error, got %v", err)
	}
}

func TestCheckIfUserIsOrgAdmin(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		if path != "orgs/acme/memberships/maintainer" {
			return fmt.Errorf("unexpected path: %s", path)
		}
		resp := response.(*MembershipResponse)
		resp.Role = "admin"
		resp.Organization.Login = "acme"
		return nil
	}})

	isAdmin, err := checkIfUserIsOrgAdmin(context.Background(), "acme", "maintainer")
	if err != nil {
		t.Fatalf("checkIfUserIsOrgAdmin() error = %v", err)
	}
	if !isAdmin {
		t.Fatal("expected org admin to be true")
	}
}

func TestCheckIfUserIsOrgAdminReturnsFalseForMissingMembership(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		return api.HTTPError{StatusCode: http.StatusNotFound, Message: "Not Found"}
	}})

	isAdmin, err := checkIfUserIsOrgAdmin(context.Background(), "acme", "maintainer")
	if err != nil {
		t.Fatalf("checkIfUserIsOrgAdmin() error = %v", err)
	}
	if isAdmin {
		t.Fatal("expected org admin to be false when membership is missing")
	}
}

func TestListAuthsForbiddenSuggestsAdminAccess(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		return api.HTTPError{StatusCode: http.StatusForbidden, Message: "Resource not accessible by integration"}
	}})

	_, err := listAuths(context.Background(), "acme")
	if err == nil {
		t.Fatal("expected listAuths() to return an error")
	}
	if !shouldRepromptOrg(err) {
		t.Fatalf("expected org reprompt error, got %v", err)
	}
	if !strings.Contains(err.Error(), "does not appear to be an admin") {
		t.Fatalf("expected admin guidance, got %v", err)
	}
}

func TestPromptForTokenRepromptsUntilValid(t *testing.T) {
	answers := []string{"", "short", "deadbeef"}
	calls := 0
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		responsePtr := response.(*string)
		*responsePtr = answers[calls]
		calls++
		return nil
	})

	token, err := promptForToken(context.Background())
	if err != nil {
		t.Fatalf("promptForToken() error = %v", err)
	}
	if token != "deadbeef" {
		t.Fatalf("promptForToken() = %q, want %q", token, "deadbeef")
	}
	if calls != 3 {
		t.Fatalf("expected 3 prompt attempts, got %d", calls)
	}
}

func TestPromptForOrgHandlesInterrupt(t *testing.T) {
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		return terminal.InterruptErr
	})

	_, err := promptForOrg(context.Background(), nil)
	if err == nil {
		t.Fatal("expected promptForOrg() to return an error")
	}
	if err != errCancelled {
		t.Fatalf("expected cancellation error, got %v", err)
	}
}

func TestPromptForOrgSelectsSuggestion(t *testing.T) {
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		if sel, ok := prompt.(*survey.Select); ok {
			if sel.Message != "Select the org you want to revoke access to:" {
				return fmt.Errorf("unexpected select message: %s", sel.Message)
			}
			*(response.(*string)) = "acme"
			return nil
		}
		return fmt.Errorf("unexpected prompt type: %T", prompt)
	})

	org, err := promptForOrg(context.Background(), []string{"acme", "globex"})
	if err != nil {
		t.Fatalf("promptForOrg() error = %v", err)
	}
	if org != "acme" {
		t.Fatalf("promptForOrg() = %q, want %q", org, "acme")
	}
}

func TestPromptForOrgManualEntryFromSuggestions(t *testing.T) {
	calls := 0
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		calls++
		switch calls {
		case 1:
			// First call: select prompt, user picks manual entry
			*(response.(*string)) = enterManuallyOption
			return nil
		case 2:
			// Second call: input prompt for manual org name
			*(response.(*string)) = "custom-org"
			return nil
		default:
			return fmt.Errorf("unexpected call %d", calls)
		}
	})

	org, err := promptForOrg(context.Background(), []string{"acme"})
	if err != nil {
		t.Fatalf("promptForOrg() error = %v", err)
	}
	if org != "custom-org" {
		t.Fatalf("promptForOrg() = %q, want %q", org, "custom-org")
	}
	if calls != 2 {
		t.Fatalf("expected 2 prompt calls, got %d", calls)
	}
}

func TestPromptForOrgNoSuggestionsFallsBackToInput(t *testing.T) {
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		if _, ok := prompt.(*survey.Input); !ok {
			return fmt.Errorf("expected Input prompt when no suggestions, got %T", prompt)
		}
		*(response.(*string)) = "typed-org"
		return nil
	})

	org, err := promptForOrg(context.Background(), nil)
	if err != nil {
		t.Fatalf("promptForOrg() error = %v", err)
	}
	if org != "typed-org" {
		t.Fatalf("promptForOrg() = %q, want %q", org, "typed-org")
	}
}

func TestPromptForContinue(t *testing.T) {
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		c, ok := prompt.(*survey.Confirm)
		if !ok {
			return fmt.Errorf("expected Confirm prompt, got %T", prompt)
		}
		if c.Message != "test message" {
			return fmt.Errorf("unexpected message: %s", c.Message)
		}
		*(response.(*bool)) = true
		return nil
	})

	result, err := promptForContinue(context.Background(), "test message")
	if err != nil {
		t.Fatalf("promptForContinue() error = %v", err)
	}
	if !result {
		t.Fatal("expected promptForContinue() to return true")
	}
}

func TestPromptForCredentialSelection(t *testing.T) {
	matches := []AuthResponse{
		{Login: "octocat", CredentialID: 9, CredentialType: "personal access token"},
		{Login: "monalisa", CredentialID: 10, CredentialType: "personal access token"},
	}

	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		sel, ok := prompt.(*survey.Select)
		if !ok {
			return fmt.Errorf("expected Select prompt, got %T", prompt)
		}
		if len(sel.Options) != 2 {
			return fmt.Errorf("expected 2 options, got %d", len(sel.Options))
		}
		// Select the second option
		*(response.(*string)) = sel.Options[1]
		return nil
	})

	auth, err := promptForCredentialSelection(context.Background(), matches)
	if err != nil {
		t.Fatalf("promptForCredentialSelection() error = %v", err)
	}
	if auth.Login != "monalisa" || auth.CredentialID != 10 {
		t.Fatalf("unexpected auth selected: %+v", auth)
	}
}

func TestPromptForCredentialSelectionInterrupt(t *testing.T) {
	useMockSurveyAskOne(t, func(prompt survey.Prompt, response interface{}, opts ...survey.AskOpt) error {
		return terminal.InterruptErr
	})

	_, err := promptForCredentialSelection(context.Background(), []AuthResponse{
		{Login: "octocat", CredentialID: 9},
	})
	if err != errCancelled {
		t.Fatalf("expected cancellation error, got %v", err)
	}
}

func TestListUserOrgsWithClient(t *testing.T) {
	client := mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		if path != "user/orgs" {
			return fmt.Errorf("unexpected path: %s", path)
		}
		resp := response.(*[]OrgResponse)
		*resp = []OrgResponse{{Login: "acme"}, {Login: "globex"}}
		return nil
	}}

	orgs, err := listUserOrgsWithClient(context.Background(), client)
	if err != nil {
		t.Fatalf("listUserOrgsWithClient() error = %v", err)
	}
	if len(orgs) != 2 || orgs[0].Login != "acme" || orgs[1].Login != "globex" {
		t.Fatalf("unexpected orgs: %+v", orgs)
	}
}

func TestListUserOrgsWithClientError(t *testing.T) {
	client := mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		return api.HTTPError{StatusCode: http.StatusUnauthorized, Message: "Bad credentials"}
	}}

	_, err := listUserOrgsWithClient(context.Background(), client)
	if err == nil {
		t.Fatal("expected listUserOrgsWithClient() to return an error")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestFetchOrgSuggestionsReturnsNames(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		if path == "user/orgs" {
			resp := response.(*[]OrgResponse)
			*resp = []OrgResponse{{Login: "acme"}, {Login: "globex"}}
			return nil
		}
		return fmt.Errorf("unexpected path: %s", path)
	}})

	names := fetchOrgSuggestions(context.Background())
	if len(names) != 2 || names[0] != "acme" || names[1] != "globex" {
		t.Fatalf("unexpected suggestions: %v", names)
	}
}

func TestFetchOrgSuggestionsReturnsNilOnError(t *testing.T) {
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		return api.HTTPError{StatusCode: http.StatusUnauthorized}
	}})

	names := fetchOrgSuggestions(context.Background())
	if names != nil {
		t.Fatalf("expected nil on error, got %v", names)
	}
}

func TestRevokeAuthUsesNumericCredentialID(t *testing.T) {
	called := false
	useMockRESTClient(t, mockRESTClient{doWithContext: func(ctx context.Context, method, path string, body io.Reader, response interface{}) error {
		called = true
		if method != http.MethodDelete {
			return fmt.Errorf("unexpected method: %s", method)
		}
		wantPath := "orgs/acme/credential-authorizations/42"
		if path != wantPath {
			return fmt.Errorf("path = %s, want %s", path, wantPath)
		}
		return nil
	}})

	if err := revokeAuth(context.Background(), "acme", 42); err != nil {
		t.Fatalf("revokeAuth() error = %v", err)
	}
	if !called {
		t.Fatal("expected revokeAuth() to call the REST client")
	}
}
