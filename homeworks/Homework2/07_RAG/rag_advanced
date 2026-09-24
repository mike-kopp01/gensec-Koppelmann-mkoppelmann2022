try:
    import readline  # noqa: F401  (not available on Windows; harmless to skip)
except ImportError:
    pass

from langchain_core.output_parsers import StrOutputParser

from advanced import TECHNIQUES, retrieve
from models import PROVIDER, get_llm
from rag_chain import build, format_docs, prompt

vectorstore, retriever, _ = build()

llm = get_llm()
answer_chain = prompt | llm | StrOutputParser()


def show_sources(docs):
    for rank, doc in enumerate(docs, start=1):
        page = f" p.{doc.metadata['page']}" if "page" in doc.metadata else ""
        print(f"  {rank}. {doc.metadata.get('source', '?')}{page}")


def ask(technique, question, with_answer):
    docs, notes = retrieve(technique, question, retriever, llm)
    for note in notes:
        print(note)
    print(f"Retrieved ({technique}):")
    show_sources(docs)
    if with_answer:
        print("Answer:", answer_chain.invoke({"context": format_docs(docs), "question": question}))


def compare(question):
    for technique in TECHNIQUES:
        print(f"\n=== {technique} ===")
        try:
            docs, notes = retrieve(technique, question, retriever, llm)
            for note in notes:
                print(note)
            show_sources(docs)
        except Exception as err:
            print(f"  Error: {err}")


mode, with_answer = "fusion", True
print(__doc__)
print(f"Provider: {PROVIDER}. Current technique: {mode}")
while True:
    try:
        line = input(f"[{mode}]>> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not line:
        break
    try:
        if line.startswith("/mode"):
            choice = line.split(maxsplit=1)[1] if " " in line else ""
            if choice in TECHNIQUES:
                mode = choice
                print(f"Technique: {mode}")
            else:
                print(f"Choose one of: {', '.join(TECHNIQUES)}")
        elif line.startswith("/compare"):
            question = line[len("/compare"):].strip()
            compare(question) if question else print("Usage: /compare <question>")
        elif line.startswith("/answer"):
            with_answer = not line.endswith("off")
            print(f"Answers {'on' if with_answer else 'off'}")
        else:
            ask(mode, line, with_answer)
    except Exception as err:
        print(f"Error: {type(err).__name__}: {err}")
