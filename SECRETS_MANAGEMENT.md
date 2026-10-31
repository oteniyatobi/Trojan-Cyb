# Secrets Management

Real secrets live only in `.env`, which is git-ignored. The repo contains `.env.example`, a template with placeholder values.

## Which secrets exist

| Variable | Shared or personal | Notes |
|---|---|---|
| `DB_PASSWORD` | Personal (local dev) | Anything you like locally. Production gets a generated value. |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | Shared | `admin/admin` is for local development only. |
| `GROQ_API_KEY` | Shared | Owned by the teammate who manages the AI engine. |

## Setup

1. Copy the template:
   ```bash
   cp .env.example .env
   ```
2. Replace the placeholders in `.env` with real values.
3. Confirm Git ignores it:
   ```bash
   git check-ignore -v .env   # should print a .gitignore line
   git status                 # .env must NOT appear
   ```

## What goes where

- **`.env.example`** (committed): variable names and fake values only.
- **`.env`** (never committed): real values, one copy per machine.

## Getting shared secrets

Shared secrets are handed over through **one channel only**: a shared password manager (e.g. a Bitwarden collection) or in person. Never send them through Slack, WhatsApp, email, GitHub issues, or PR comments, because those are hard to fully delete.

## Generating strong values

```bash
openssl rand -base64 32
```

## If a secret is committed or leaked

1. **Revoke and regenerate it first.** Do this before anything else. Once pushed, assume it is compromised.
2. Tell the team, and update `.env` for everyone who uses it.
3. Optionally remove it from Git history with `git filter-repo` or BFG. Deleting the file in a new commit is not enough, because the old commit still contains it. Rotation matters more than scrubbing.

## Automated protection

- Run a secret scanner before commits, e.g. [gitleaks](https://github.com/gitleaks/gitleaks) as a pre-commit hook.
- Enable GitHub secret scanning and push protection on the repo if the plan supports it.

## Review rule

When reviewing a PR, check that `.env.example` contains **placeholders only**. This is where real values most often leak by accident, when someone copies their `.env` into the template.

## Production

- Never deploy a `.env` copied from a laptop. Generate fresh values on the server.
- Store the Groq key in a file only the service can read (`chmod 600`, owned by the service user), loaded as an environment file or Docker secret. Not inside a repo checkout.
- Change every default credential (including Wazuh `admin/admin`) before the server is reachable by anyone else.
