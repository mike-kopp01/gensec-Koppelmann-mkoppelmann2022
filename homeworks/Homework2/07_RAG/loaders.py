from __future__ import annotations

import csv
import io
import os
from pathlib import Path
from typing import Iterator

import requests
from langchain_core.document_loaders import BaseLoader
from langchain_core.documents import Document

USER_AGENT = "gensec-rag/1.0 (educational RAG lab)"
TIMEOUT = 30


def _read_text(path: Path) -> str:
    """Read a text file as UTF-8, falling back to Latin-1 (never fails on Windows)."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def _source(path: Path, base: Path | None) -> str:
    """Short, portable source name like 'rag_data/txt/x.txt'."""
    if base is not None:
        try:
            return path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            pass
    return path.as_posix()


class DirectoryTextLoader(BaseLoader):
    """Load every text file matching a pattern (.txt, .md, ...), one Document per file."""

    def __init__(self, directory, pattern: str = "*.txt", base: Path | None = None):
        self.directory, self.pattern, self.base = Path(directory), pattern, base

    def lazy_load(self) -> Iterator[Document]:
        for path in sorted(self.directory.rglob(self.pattern)):
            yield Document(page_content=_read_text(path), metadata={"source": _source(path, self.base)})


class PDFLoader(BaseLoader):
    """Load PDFs with pypdf, one Document per page. Pages with no text (scans) are skipped."""

    def __init__(self, directory, base: Path | None = None):
        self.directory, self.base = Path(directory), base

    def lazy_load(self) -> Iterator[Document]:
        from pypdf import PdfReader

        for path in sorted(self.directory.rglob("*.pdf")):
            for number, page in enumerate(PdfReader(path).pages, start=1):
                text = (page.extract_text() or "").strip()
                if text:
                    yield Document(page_content=text, metadata={"source": _source(path, self.base), "page": number})


class DocxLoader(BaseLoader):
    """Load Word .docx files with docx2txt, one Document per file."""

    def __init__(self, directory, base: Path | None = None):
        self.directory, self.base = Path(directory), base

    def lazy_load(self) -> Iterator[Document]:
        import docx2txt

        for path in sorted(self.directory.rglob("*.docx")):
            yield Document(page_content=docx2txt.process(str(path)), metadata={"source": _source(path, self.base)})


class CSVRowLoader(BaseLoader):
    """Load CSV files, one Document per row, formatted as 'column: value' lines."""

    def __init__(self, directory, base: Path | None = None):
        self.directory, self.base = Path(directory), base

    def lazy_load(self) -> Iterator[Document]:
        for path in sorted(self.directory.rglob("*.csv")):
            reader = csv.DictReader(io.StringIO(_read_text(path)))
            for row_number, row in enumerate(reader):
                text = "\n".join(f"{key}: {value}" for key, value in row.items())
                yield Document(page_content=text, metadata={"source": _source(path, self.base), "row": row_number})


class WebPageLoader(BaseLoader):
    """Download web pages and keep only readable text.

    Uses the <article> element when a page has one (like the transformer lesson),
    otherwise the whole <body>. Scripts, styles, and navigation are dropped.
    """

    def __init__(self, urls: list[str]):
        self.urls = urls

    def lazy_load(self) -> Iterator[Document]:
        from bs4 import BeautifulSoup

        for url in self.urls:
            response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            for tag in soup(["script", "style", "nav", "header", "footer", "noscript"]):
                tag.decompose()
            root = soup.find("article") or soup.body or soup
            text = "\n".join(line.strip() for line in root.get_text("\n").splitlines() if line.strip())
            title = soup.title.get_text(strip=True) if soup.title else url
            yield Document(page_content=text, metadata={"source": url, "title": title})


class ArxivPaperLoader(BaseLoader):
    """Download an arXiv paper's PDF by ID (e.g. '2310.03714') and extract its text."""

    def __init__(self, paper_id: str):
        self.paper_id = paper_id

    def lazy_load(self) -> Iterator[Document]:
        from pypdf import PdfReader

        url = f"https://arxiv.org/pdf/{self.paper_id}"
        response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        response.raise_for_status()
        reader = PdfReader(io.BytesIO(response.content))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        yield Document(page_content=text, metadata={"source": f"arxiv:{self.paper_id}", "url": url})


class GitHubFileLoader(BaseLoader):
    """Load files from a GitHub repo whose path ends with a given suffix.

    Works without a token for public repos (GitHub allows 60 requests/hour);
    set GITHUB_PERSONAL_ACCESS_TOKEN for a higher limit or private repos.
    """

    def __init__(self, repo: str, suffix: str, branch: str = "main"):
        self.repo, self.suffix, self.branch = repo, suffix, branch

    def lazy_load(self) -> Iterator[Document]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        token = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        tree_url = f"https://api.github.com/repos/{self.repo}/git/trees/{self.branch}?recursive=1"
        response = requests.get(tree_url, headers=headers, timeout=TIMEOUT)
        if response.status_code != 200:
            raise RuntimeError(f"GitHub API {response.status_code}: {response.json().get('message', '')}")
        for item in response.json().get("tree", []):
            if item["type"] == "blob" and item["path"].endswith(self.suffix):
                raw = f"https://raw.githubusercontent.com/{self.repo}/{self.branch}/{item['path']}"
                file_response = requests.get(raw, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
                file_response.raise_for_status()
                yield Document(
                    page_content=file_response.text,
                    metadata={"source": f"github:{self.repo}/{item['path']}", "url": raw},
                )


class YouTubeTranscriptLoader(BaseLoader):
    """Load a YouTube video's transcript as one Document."""

    def __init__(self, video_id: str):
        self.video_id = video_id

    def lazy_load(self) -> Iterator[Document]:
        from youtube_transcript_api import YouTubeTranscriptApi

        transcript = YouTubeTranscriptApi().fetch(self.video_id)
        text = " ".join(entry.text for entry in transcript)
        yield Document(page_content=text, metadata={"source": f"youtube:{self.video_id}"})
