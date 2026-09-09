import logging

from llm.llm_service import LLMService
from utils.logger import get_logger

logger=get_logger("generator","generator.log")

class Generator:
    """Generate response using retrieved context and other context"""
    def __init__(self):
        logger.info("Initializing Generator...")
        self.llm_service=LLMService()
        logger.info("Generator initialized successfully")

    def generate(self, query, context):
        """
        Generate a response based on the user query and retrieved context.
        
        Args:
            query(str): User's question.
            context(str): Relevant context retrieved from the vector databse.

        Returns:
            str: Generated LLM response.
        """

        logger.info("Generating response...")
        prompt=self._build_prompt(query, context)
        response=self.llm_service.generate(prompt)
        logger.info("Response generated successfully")
        return response

    def _build_prompt(self, query, context):
        """
        Build the prompt sent to the LLM.
        """
        prompt=f"""
You are a helpful AI assistant.

Answer the user's question using ONLY the provided context.

If the answer cannot be found in the context, say:

"I don't have enough information in the provided context to answer this question."

Do not make up information.
Do not use knowledge outside the provided context.

Context:
{context}

Question:
{query}

Answer:
"""
        return prompt.strip()