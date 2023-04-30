# gh revoke

A gh cli extension that a will guide an org admin through the process of revoking SSO from a leaked PAT. 


## Features

- prompts users for name and PAT
- supports full 40 char PAT & last 8 chars of PAT
- outputs user of matching

## install

`gh ext install pmartindev/gh-revoke`

## Usage 

`gh revoke `

Begins the series of prompts.

## TODO
- [ ] support for multiple PATs
- [ ] suggestions for possible orgs
    - [ ] support for multiple orgs
- [ ] logic to reprompt for invalid input
    - [ ] exit on keyboard interrupt
- [ ] suggestions for possible users