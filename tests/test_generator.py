from rag.generator import Generator 
from rag.retriever import Retriever
from utils.logger import get_logger  

def test_generator():
    print("--- Generator test started ---")

    #Initializing components
    retriever=Retriever()
    generator=Generator()

    query="What is prompt injection?"

    #Retrieve relevant document chunks
    documents=retriever.retrieve(query)

    if not documents:
        print("No relevant documents found for the query.")
        return

    print(f"Retrieved {len(documents)} documents.")

    #Combine retrieved document chunks into context
    context="\n\n".join(document.page_content for document in documents)

    #Generate response
    print("Sending retrieved context to Generator...")

    response=generator.generate(query=query, context=context)

    print("--- Generated Response ---")
    print(response)

    print("--- Generator Integration Test Completed Successfully ---")

if __name__=="__main__":
    test_generator()