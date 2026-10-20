"""Self-contained Git MCP server (stdio) for use in VS Code."""

import os
from fastmcp import FastMCP
import git

# Default repo = the folder VS Code has open (GIT_REPO env var), else current dir.
DEFAULT_REPO = os.getenv("GIT_REPO") or "."

mcp = FastMCP("git-server")


def _repo(repo_path: str = "") -> git.Repo:
    return git.Repo(repo_path or DEFAULT_REPO, search_parent_directories=True)


@mcp.tool()
def git_status(repo_path: str = "") -> str:
    """Show the working-tree status of the git repository."""
    return _repo(repo_path).git.status()


@mcp.tool()
def git_last_commit_hash(repo_path: str = "") -> str:
    """Return the full SHA hash of the latest (HEAD) commit."""
    return _repo(repo_path).head.commit.hexsha


@mcp.tool()
def git_log(repo_path: str = "", max_count: int = 20) -> str:
    """List recent commits as: short-hash, author name <email>, summary."""
    repo = _repo(repo_path)
    lines = [
        f"{c.hexsha[:10]}  {c.author.name} <{c.author.email}>  {c.summary}"
        for c in repo.iter_commits(max_count=max_count)
    ]
    return "\n".join(lines) if lines else "(no commits)"


@mcp.tool()
def git_authors(repo_path: str = "", max_count: int = 20) -> str:
    """List the distinct commit authors across the last `max_count` commits."""
    repo = _repo(repo_path)
    seen: dict[str, None] = {}
    for c in repo.iter_commits(max_count=max_count):
        seen.setdefault(f"{c.author.name} <{c.author.email}>", None)
    return "\n".join(seen) if seen else "(no commits)"


@mcp.tool()
def git_diff(repo_path: str = "") -> str:
    """Show the unstaged diff (working-tree changes) of the repository."""
    return _repo(repo_path).git.diff() or "(no unstaged changes)"


if __name__ == "__main__":
    mcp.run(transport="stdio")
