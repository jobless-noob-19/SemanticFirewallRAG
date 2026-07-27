from rag.Ingestion.loader import DocumentLoader
from rag.Ingestion.splitter import DocumentSplitter

loader=DocumentLoader()
documents=loader.load_documents()
splitter = DocumentSplitter()  
chunks = splitter.split_documents(documents)
print(f"Total chunks: {len(chunks)}")
print("\nFirst Chunk\n")
print(chunks[0].page_content)
print("\nMetadata\n")
print(chunks[0].metadata)