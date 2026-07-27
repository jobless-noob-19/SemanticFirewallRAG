from rag.Ingestion.loader import DocumentLoader
loader=DocumentLoader()
documents=loader.load_documents()
print(documents[0].page_content)
print(documents[0].metadata)