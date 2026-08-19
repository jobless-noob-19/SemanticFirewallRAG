from embeddings.embedding_service import EmbeddingService
def test_embedding_service():
    try:
        embedding_service=EmbeddingService()
        embedding_model=embedding_service.get_embedding_model()
        query="What is prompt injection?"
        vector=embedding_model.embed_query(query)
        print("\n=== Embedding test passed ===")
        print(f"Query: {query}")
        print(f"Embedding Dimension: {len(vector)}")
        print(f"First 10 values: {vector[:10]}")
        assert isinstance(vector,list),"Embedding is not a list."
        assert len(vector)>0, "Embedding vector is empty."
        print("All test passed successfully!")
    except Exception as e:
        print("\n=== Embedding test failed ===")
        print(f"Error: {e}")

if __name__=="__main__":
    test_embedding_service()
