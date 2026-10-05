# Homework 3: Security Recon Assistant

**Author:** Michael Koppelmann

The Security Recon Assistant is a command-line AI agent built with LangChain and LangGraph. It answers security-research questions using real data sources instead of guessing. Google's Gemini model picks the right tool for each question: it can search the web, find academic papers, look up a domain's DNS records, get vulnerability details and CVSS scores from the NIST National Vulnerability Database, and run Python code for calculations. Running code is dangerous, so every Python call pauses for the user to approve it or give feedback. When a call is rejected, the agent revises its plan.

## Features

- **Five tools**: two built-in LangChain tools that the lab didn't use, two custom tools, and the Python REPL.
- **Custom LangGraph architecture** with a human-approval step.
- **Per-call approval**: every Python call is shown to the user and must be approved before it runs.
- **Feedback loop**: rejecting a call sends your feedback to the model, which proposes a revised call.
- **Conversation memory**: follow-up questions can refer to earlier answers in the same session.
- **No secrets in code**: API keys are read only from environment variables.

## Tools

| Tool | Type | What it does |
|---|---|---|
| `duckduckgo_search` | Built-in (new, not in the lab) | Web search for current events and general information. No API key needed. |
| `arxiv` | Built-in (new, not in the lab) | Searches academic papers on arXiv. |
| `dns_lookup` | Custom (`@tool`) | Returns a domain's A, AAAA, MX, NS, TXT, CNAME, SOA or CAA records using `dnspython`. |
| `cve_lookup` | Custom (`@tool`) | Gets a CVE's description, CVSS score, severity, publication date and references from the NIST NVD API. |
| `Python_REPL` | Required (kept from the lab) | Runs Python code for calculations and data processing. **Needs user approval for every call.** |

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

| Node | Role |
|---|---|
| `call` | Gemini, with all tools bound, either gives a final answer or proposes tool calls. |
| `tools` | LangGraph's prebuilt `ToolNode` runs the requested tools, then returns to `call`. |
| `human_review` | Pauses with `interrupt()` for every Python call. Typing `y` runs the tools; anything else is sent back to the model as feedback. |

**Routing:** if the model proposes no tool calls, the run ends. Lookups (search, arXiv, DNS, CVE) run straight away. Any step that includes a Python call goes to `human_review` first.

**Memory:** a `MemorySaver` checkpointer stores the conversation for the session and lets an interrupted run resume after you answer.

## Security design

| Risk | How the agent handles it |
|---|---|
| The model runs harmful code | Every `Python_REPL` call needs explicit approval. In the lab's `07_langgraph_feedback.py`, only the first of several calls was shown, but approving ran all of them. Here each call is reviewed individually. |
| Prompt injection from web pages | The system prompt tells the model to treat tool output as untrusted data and never follow instructions inside it. |
| Runaway tool loops | A hard `recursion_limit` of 30 graph steps per request. The lab's "at most 8 tool calls" was only a request in the prompt and wasn't enforced. |
| Bad tool input | CVE IDs must match `CVE-YYYY-NNNN`, and only known DNS record types are accepted. |
| Outdated "current year" | The system prompt includes today's date. In the lab, the agent answered that Taylor Swift was 34 instead of 36 because it assumed the year was 2024. |
| Leaked API keys | Keys come from environment variables (or a gitignored `.env` file), never from the code. |

## Project files

| File | Purpose |
|---|---|
| `app.py` | The complete agent: tools, graph, approval step and console interface. |
| `pyproject.toml`, `uv.lock` | Dependencies, managed with `uv`. |
| `.vscode/` | VS Code run configuration and interpreter settings. |
| `.env.example` | Template for your API key (copy it to `.env`). |
| `screencast_url.txt` | Link to the demo screencast. |

## Setup

### Requirements

- [uv](https://docs.astral.sh/uv/)
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)

### Linux / VM

```bash
export GOOGLE_API_KEY="your-key"
export GOOGLE_MODEL="gemini-flash-lite-latest"
cd homeworks/Homework3
uv sync
uv run app.py
```

### Windows / VS Code

1. Open `homeworks/Homework3` in VS Code and install the recommended Python extensions if prompted.
2. Run `uv sync` in the terminal to create `.venv`.
3. Copy `.env.example` to `.env` and paste in your API key.
4. Press **F5** (or **Run and Debug → Run Security Recon Assistant**).

## Usage

Type a question at the `llm>>` prompt. The agent prints each tool call and result, then its final answer. Press Enter on an empty line to quit.

When the agent wants to run Python, it shows the code and asks:

```
[Approval needed] Python_REPL wants to run:
print(2**10)
Type 'y' to approve, or describe the change you want:
```

- Type **`y`** to run it.
- Type anything else, for example `use a loop instead`, and the model will propose a revised call.
