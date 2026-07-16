import ollama 
response=ollama.chat(
    model="llama3.2",
    messages=[
        {
            "role":"user",
            "content":"Hello! Can you confirm you are working?"
        }
    ]
)
print(response["message"]["content"])