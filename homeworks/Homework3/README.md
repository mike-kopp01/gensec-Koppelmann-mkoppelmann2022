# Homework 3: Security Recon Assistant

A LangGraph agent that answers security-research questions with built-in and custom LangChain tools. It runs Python code only after a human approves each call.

## Tools

| Tool | Type | Purpose |
|---|---|---|
| `duckduckgo_search` | Built-in (not in the lab) | Web search, no API key needed |
| `arxiv` | Built-in (not in the lab) | Academic paper search |
| `dns_lookup` | Custom (`@tool`) | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records via `dnspython` |
| `cve_lookup` | Custom (`@tool`) | CVE details and CVSS score from the NIST NVD API |
| `Python_REPL` | Required (kept from the lab) | Runs Python code, **gated behind human approval** |

## Architecture

```mermaid
graph TD;
    __start__ --> call;
    call -.-> __end__;
    call -.-> human_review;
    call -.-> tools;
    human_review -.-> call;
    human_review -.-> tools;
    tools --> call;
```

- **`call`**: Gemini, with all tools bound, either answers or proposes tool calls.
- **Routing**: safe lookups go straight to `tools`; any `Python_REPL` call goes to `human_review`.
- **`human_review`**: uses LangGraph `interrupt()` to pause for **every** dangerous call in the step. If you type `y`, the tools run. Anything else is sent back to the model as feedback, and **every** pending `tool_call_id` gets a reply.
- **`tools`**: the prebuilt `ToolNode` runs the calls, then control returns to `call`.
- **Memory**: a `MemorySaver` checkpointer keeps the conversation for the session and makes interrupts resumable.

### Improvements over the lab examples

| Issue seen in the lab | Fix in this agent |
|---|---|
| `07_langgraph_feedback.py` only showed `tool_calls[0]`, but approval ran **all** calls | Every dangerous call is reviewed individually |
| `02_tools_builtin.py` answered "34" for Taylor Swift's age (the model assumed the year was 2024) | The system prompt includes today's date |
| "At most 8 tool calls" was only a prompt instruction | Enforced `recursion_limit` |
| Tool output (web pages) can contain prompt injection | The system prompt marks tool output as untrusted data |
| Gemini content blocks printed raw (`[{'type': 'text', ...}]`) | Plain-text extraction |

## Setup

API keys are read from environment variables only:

```bash
export GOOGLE_API_KEY="your-key"
export GOOGLE_MODEL="gemini-flash-lite-latest"
```

Install and run with `uv`:

```bash
cd homeworks/Homework3
uv sync
uv run app.py
```

### VS Code

1. Open this folder in VS Code: `code homeworks/Homework3`. Install the recommended Python extensions if prompted.
2. Run `uv sync` once to create `.venv`. VS Code picks it up as the interpreter (`.vscode/settings.json`).
3. Copy `.env.example` to `.env` and fill in your key. `.env` is gitignored.
4. Press **F5** (or **Run and Debug → Run Security Recon Assistant**). The agent runs in the integrated terminal, so you can type prompts and approvals there.

## Example prompts

- `What is CVE-2021-44228 and how severe is it?`: uses `cve_lookup`
- `Which mail servers and SPF record does fau.edu use?`: uses `dns_lookup` (MX + TXT)
- `Find recent arXiv papers on prompt injection defenses`: uses `arxiv`
- `Look up CVE-2014-0160 and use Python to compute how many days ago it was published`: uses `cve_lookup`, then `Python_REPL` (approval prompt)
- `Write a Python one-liner that deletes foo`: answer with feedback instead of `y` to see the model revise its call
