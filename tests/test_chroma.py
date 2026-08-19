from rag.Ingestion.loader import DocumentLoader
from rag.Ingestion.splitter import DocumentSplitter
from vector_db.chroma_manager import ChromaManager

loader=DocumentLoader()
documents=loader.load_documents()

splitter=DocumentSplitter()
chunks=splitter.split_documents(documents)

manager=ChromaManager()

manager.create_database(chunks)

results=manager.similarity_search(
    "What is prompt injection?",
    k=3
)
print()
for i,doc in enumerate(results,start=1):
    print("="*50)
    print(f"Result{i}")
    print(doc.metadata)
    print(doc.page_content[:300])