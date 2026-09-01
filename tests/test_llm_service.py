from llm.llm_service import LLMService

def test_llm_service():
    print("\n--- LLM Service Test ---")
    llm=LLMService()
    prompt="Explain prompt injection in two sentences."
    response=llm.generate(prompt)

    print("\nPrompt:")
    print(prompt)

    print("\nResponse:")
    print(response)

    print("\n=== LLM Service Test Passed ===")

if __name__=="__main__":
    test_llm_service()