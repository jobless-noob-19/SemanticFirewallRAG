from rag.rag_pipeline import RAGPipeline

def test_rag__pipeline():
    print("\n--- RAG Pipeline Test started ---\n")
    pipeline=RAGPipeline()
    query="What is prompt injection?"
    print("User Query:")
    print(query)
    print("\nRunning RAG Pipeline...")
    response=pipeline.run(query)
    print("\n--- RAG Response ---")
    print(response)
    print("\n--- RAG Pipeline test completed successfully ---")

if __name__=="__main__":
    test_rag__pipeline()