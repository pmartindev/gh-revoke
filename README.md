# gh revoke

`gh revoke` is a GitHub CLI extension that guides an organization admin through revoking SSO authorization for a leaked personal access token.

## What it does

- fetches your organizations and presents them as selectable suggestions
- accepts either the full 40-character PAT or just the last 8 characters
- verifies the currently authenticated `gh` user is an admin of the organization
- finds matching credential authorizations and shows associated user info
- when multiple credentials match, lets you select which one to revoke
- confirms before revoking access
- after revoking, offers to revoke another token in the same or a different organization
- supports batch revocation of multiple tokens across multiple orgs in one session
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

1. fetch your organizations and present them as a selectable list (or let you type a name)
2. prompt for the leaked PAT (full token or last 8 characters)
3. verify your current `gh` login has org admin access
4. locate matching credential authorizations (if multiple match, present a selection)
5. display the associated user and credential info
6. ask for confirmation before revoking access
7. offer to revoke another token (same org or a different one)

Demo:

![](images/gh-revoke-demo.gif)

## Example prompt flow

```text
$ gh revoke
? Select the org you want to revoke access to:
  > octo-org
    globex-corp
    [Enter a different org name]
? Enter the GitHub personal access token to be revoked: ********
✓ Token found for user: octocat (credential type: personal access token)
? Are you sure you want to revoke access for user: octocat? Yes
✓ Token revoked for user: octocat
? Would you like to revoke another token? Yes
? Continue with organization "octo-org"? No
? Select the org you want to revoke access to: globex-corp
? Enter the GitHub personal access token to be revoked: ********
✓ Token found for user: hubot (credential type: personal access token)
? Are you sure you want to revoke access for user: hubot? Yes
✓ Token revoked for user: hubot
? Would you like to revoke another token? No
```

### Multiple credential matches

When multiple credentials share the same last 8 characters, you can select which one to revoke:

```text
✓ Found 2 credentials ending in deadbeef
? Multiple credentials found. Select the one to revoke:
  > octocat (credential ID: 9, type: personal access token)
    monalisa (credential ID: 10, type: personal access token)
```

## Error handling

The extension handles common failure cases clearly:

- empty or malformed input is rejected and reprompted
- invalid or inaccessible organizations show a clearer message
- non-admin users are told why the revoke cannot proceed
- GitHub auth and network failures return more actionable errors
- `Ctrl+C` cancels the flow gracefully

## Notes

- the extension uses the account already authenticated in `gh`
- it matches authorizations by the token's last 8 characters
- when multiple credentials match, you are prompted to select the correct one
- it does not push changes, create pull requests, or modify any GitHub settings beyond the requested revoke action
