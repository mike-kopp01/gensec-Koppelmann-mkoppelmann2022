# Git MCP Server (VS Code)

A self-contained [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes read-only Git tools to an AI agent (GitHub Copilot's **Agent mode**) inside
VS Code. It lets the agent inspect a repository — status, commit history, authors,
diffs — by calling structured tools rather than running arbitrary shell commands.

> Built for a security exercise: an official, non-malicious MCP server was selected,
> **scanned before running**, and then re-implemented as this minimal local server.

---

## What it does

The server speaks MCP over **stdio**. VS Code launches it and the agent calls its tools.
Each tool operates on a Git repository — the path passed in, or the `GIT_REPO`
environment variable (wired to the open VS Code folder via `${workspaceFolder}`).

| Tool | Description |
|------|-------------|
| `git_status` | Working-tree status of the repository |
| `git_last_commit_hash` | Full SHA of the latest (HEAD) commit |
| `git_log` | Recent commits: short-hash, author, summary |
| `git_authors` | Distinct authors across the last N commits |
| `git_diff` | Unstaged (working-tree) changes |

All tools are **read-only** — the server performs no writes, no network calls, and
no shell execution. Git is accessed through the GitPython API (arguments passed as a
list, so there is no shell-injection surface).

---

## Files

```
git-server/
├─ git_mcp_server.py   # the server (≈70 lines, FastMCP + GitPython)
└─ README.md           # this file
```

---

## Requirements

- **[uv](https://docs.astral.sh/uv/)** (installed at `C:\Users\pacif\.local\bin\uv.exe`).
  `uv` auto-installs the server's dependencies (`fastmcp`, `gitpython`) into a
  throwaway environment on each launch — nothing to pip-install manually.
- **VS Code** with **GitHub Copilot** (Agent mode uses MCP tools).
- **Git** on the system.

---

## Setup — VS Code

Add the server to your VS Code MCP config at
`%APPDATA%\Code\User\mcp.json` (Command Palette → **MCP: Open User Configuration**):

```json
{
  "servers": {
    "git-server": {
      "type": "stdio",
      "command": "C:\\Users\\pacif\\.local\\bin\\uv.exe",
      "args": [
        "run", "--with", "fastmcp", "--with", "gitpython",
        "python", "C:\\Users\\pacif\\mcp-servers\\git-server\\git_mcp_server.py"
      ],
      "env": { "GIT_REPO": "${workspaceFolder}" }
    }
  }
}
```

Then:

1. Command Palette → **Developer: Reload Window**.
2. Open a Git repository folder (so `${workspaceFolder}` resolves).
3. Command Palette → **MCP: List Servers** → `git-server` → **Start**.
4. Open **Copilot Chat**, switch the mode dropdown to **Agent**, and ask:
   - *"What's the last commit hash?"*
   - *"List the authors of the last 20 commits."*
   - *"What's the git status of this repo?"*

The agent calls the server's tools and answers in plain language. The server is **not**
a chatbot — you talk to the agent, the agent talks to the server.

---

## Run / test manually (optional)

```bash
uv run --with fastmcp --with gitpython python git_mcp_server.py
```

It will sit silently waiting for a client — that is correct for an stdio MCP server,
not a freeze. Press `Ctrl+C` to stop. Real use is through VS Code, not by hand.

---

## Security review

This project started from the official reference server
[`mcp-server-git`](https://github.com/modelcontextprotocol/servers/tree/main/src/git)
and scanned it **before running any code**:

- **Provenance** — authored by Anthropic PBC, MIT license, maintainer `@anthropic.com`.
- **Source** — no `eval` / `exec` / `subprocess` / `os.system` / shell, no network,
  no environment exfiltration. Git runs via GitPython's argument-list API.
- **Tool surface** — scoped read/write git tools only; no "run arbitrary command"
  tool; local-only (no remote/push/pull).
- **Dependencies** — `pip-audit` reported **no known vulnerabilities**.
- **Verified** — connected over MCP, listed tools, and ran `git_status` against a
  real repository successfully.

This local re-implementation deliberately exposes **only read-only** tools, keeping
the attack surface minimal.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'fastmcp'` | You ran it with plain Python. Launch via `uv run --with fastmcp --with gitpython python ...`, which installs deps automatically. |
| Server "hangs" with no output | Expected — an stdio server waits for a client. Not an error. |
| Tools don't appear in Copilot | Reload the window; confirm a Git repo folder is open; check **MCP: List Servers**; ensure Copilot is signed in and chat is in **Agent** mode. |
| `${workspaceFolder}` empty | Open a folder (not just a loose file) in VS Code. |
