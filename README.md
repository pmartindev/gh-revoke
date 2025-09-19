# gh revoke

`gh revoke` is a GitHub CLI extension that guides an organization admin through revoking SSO authorization for a leaked personal access token.

## What it does

- prompts for the target organization and token
- accepts either the full 40-character PAT or just the last 8 characters
- verifies the currently authenticated `gh` user is an admin of the organization
- finds the matching credential authorization and confirms before revoking it
- reprompts on invalid input instead of exiting immediately
- exits cleanly on `Ctrl+C`

## Requirements

Before using the extension:

- install the [GitHub CLI](https://cli.github.com/)
- authenticate with `gh auth login`
- use a GitHub account that is an admin of the target organization and can manage SSO credential authorizations

## Install

```bash
gh ext install pmartindev/gh-revoke
```

To update later:

```bash
gh ext upgrade pmartindev/gh-revoke
```

## Usage

Run:

```bash
gh revoke
```

The extension will then:

1. prompt for the organization name
2. prompt for the leaked PAT (full token or last 8 characters)
3. verify your current `gh` login has org admin access
4. locate the matching credential authorization
5. ask for confirmation before revoking access

Demo:

![](images/gh-revoke-demo.gif)

## Example prompt flow

```text
$ gh revoke
? Enter the name of the org you want to revoke access to: octo-org
? Enter the GitHub personal access token to be revoked: ********
✓ Token found for user: octocat
? Are you sure you want to revoke access for user: octocat? Yes
✓ Token revoked for user: octocat
```

## Error handling

The extension now handles common failure cases more clearly:

- empty or malformed input is rejected and reprompted
- invalid or inaccessible organizations show a clearer message
- non-admin users are told why the revoke cannot proceed
- GitHub auth and network failures return more actionable errors
- `Ctrl+C` cancels the flow gracefully

## Notes

- the extension uses the account already authenticated in `gh`
- it currently matches a single authorization by the token's last 8 characters
- it does not push changes, create pull requests, or modify any GitHub settings beyond the requested revoke action
