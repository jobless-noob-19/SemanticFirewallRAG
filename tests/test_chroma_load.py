from vector_db.chroma_manager import ChromaManager

manager=ChromaManager()

db=manager.load_database()

result=manager.similarity_search(
    "What is prompt injection?",
    k=3
)
print()
for i,doc in enumerate(result,start=1):
    print("="*50)
    print(f"Result {i}")
    print(doc.metadata)
    print(doc.page_content[:300])