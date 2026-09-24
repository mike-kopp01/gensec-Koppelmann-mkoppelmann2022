from __future__ import annotations

import hashlib
import re

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

TECHNIQUES = ["basic", "multi_query", "fusion", "step_back", "hyde"]

multi_query_prompt = ChatPromptTemplate.from_template(
    """You are an AI assistant. Write {n} different versions of the user's question to help
retrieve relevant documents from a vector database. Use different wording and angles.
Write one question per line, with no numbering and no extra text.

Original question: {question}"""
)

step_back_prompt = ChatPromptTemplate.from_template(
    """Rewrite the question below as a broader, more general question about the underlying
topic. Reply with only the new question.

Examples:
Question: Which cereal has the most fiber per serving?
Broader: What nutritional information is known about breakfast cereals?
Question: How do I make text bold in Markdown?
Broader: How does Markdown formatting syntax work?

Question: {question}
Broader:"""
)

hyde_prompt = ChatPromptTemplate.from_template(
    """Write a short passage (about 4 sentences) that would answer the question below,
in the style of a reference document. It is fine to guess.

Question: {question}
Passage:"""
)


def _doc_key(doc) -> str:
    """Identify a chunk by its source and content, so duplicates can be merged."""
    return hashlib.sha1(f"{doc.metadata.get('source')}|{doc.page_content}".encode()).hexdigest()


def parse_questions(text: str, limit: int) -> list[str]:
    """Turn an LLM reply into a clean list of questions (strips numbering and bullets)."""
    questions = []
    for line in text.splitlines():
        line = re.sub(r"^\s*(?:\d+[.)]|[-*•])\s*", "", line).strip().strip('"')
        if len(line) > 5 and line not in questions:
            questions.append(line)
    return questions[:limit]


def unique_union(result_lists) -> list:
    """Merge several ranked lists, keeping each chunk once, in first-seen order."""
    seen, merged = set(), []
    for docs in result_lists:
        for doc in docs:
            key = _doc_key(doc)
            if key not in seen:
                seen.add(key)
                merged.append(doc)
    return merged


def reciprocal_rank_fusion(result_lists, k: int = 60) -> list[tuple]:
    """Reciprocal Rank Fusion: score = sum over lists of 1 / (k + rank).

    A chunk that ranks well in many searches beats one that ranks first in just one.
    Returns [(doc, score), ...] sorted best first.
    """
    scores, docs = {}, {}
    for result in result_lists:
        for rank, doc in enumerate(result):
            key = _doc_key(doc)
            docs[key] = doc
            scores[key] = scores.get(key, 0.0) + 1.0 / (k + rank + 1)
    return sorted(((docs[key], score) for key, score in scores.items()), key=lambda pair: pair[1], reverse=True)


def generate_queries(llm, question: str, n: int = 3) -> list[str]:
    """The original question plus up to n LLM-written rewordings."""
    reply = (multi_query_prompt | llm | StrOutputParser()).invoke({"question": question, "n": n})
    return [question] + [q for q in parse_questions(reply, n) if q != question]


def retrieve(technique: str, question: str, retriever, llm, top_k: int = 4):
    """Run one retrieval technique. Returns (documents, notes)."""
    if technique == "basic":
        return retriever.invoke(question)[:top_k], []

    if technique in ("multi_query", "fusion"):
        queries = generate_queries(llm, question)
        results = [retriever.invoke(q) for q in queries]
        notes = ["Generated queries:"] + [f"  - {q}" for q in queries]
        if technique == "multi_query":
            return unique_union(results)[:top_k], notes
        fused = reciprocal_rank_fusion(results)[:top_k]
        notes += ["RRF scores:"] + [f"  {score:.4f}  {doc.metadata.get('source')}" for doc, score in fused]
        return [doc for doc, _ in fused], notes

    if technique == "step_back":
        broader = (step_back_prompt | llm | StrOutputParser()).invoke({"question": question}).strip()
        broader = parse_questions(broader, 1)[0] if parse_questions(broader, 1) else question
        docs = unique_union([retriever.invoke(question), retriever.invoke(broader)])
        return docs[:top_k], [f"Step-back question: {broader}"]

    if technique == "hyde":
        passage = (hyde_prompt | llm | StrOutputParser()).invoke({"question": question}).strip()
        return retriever.invoke(passage)[:top_k], ["Hypothetical document used for search:", f"  {passage[:400]}"]

    raise ValueError(f"Unknown technique '{technique}'. Choose from: {', '.join(TECHNIQUES)}")
