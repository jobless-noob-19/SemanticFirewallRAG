from rag.retriever import Retriever

def main():
    print("\n --- Retriever Test ---")
    retriever=Retriever()
    query="What is prompt injection?"
    results=retriever.retrieve(query)
    print(f"\nQuery: {query}")
    print(f"Retrieved documents: {len(results)}")

    for i, document in enumerate(results, start=1):
        print(f"\n--- Result{i} ---")

        print("Content:")
        print(document.page_content)

        print("\nMetadata:")
        print(document.metadata)

if __name__=="__main__":
    main()