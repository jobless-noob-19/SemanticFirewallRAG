import ollama
from utils.logger import get_logger

logger=get_logger("llm_service","llm_service.log")

class LLMService:
    """Service responsible for communicating with the Ollama LLM."""
    def __init__(self,model: str="qwen2.5:latest"):
        """
        Initialize the LLM service.
        Args:
            model: Name of the Ollama model,
            host: Ollama server URL
        """
        logger.info(f"Initializing LLM Service with model: {model}")

        self.model=model
        logger.info("LLM Service initialized successfully")

    def generate(self,prompt: str) -> str:
        """
        Generate a response from the LLM.
        Args:
            prompt: The prompt sent to the LLM.
        Returns: Generated response as a string.
        """
        try:
            logger.info("Sending prompt to LLM")

            response=ollama.generate(
                model=self.model,
                prompt=prompt
            )

            answer=response["response"]

            logger.info("LLM response generated successfully")

            return answer
        except Exception as e:
            logger.error(f"Error generating LLM response: {e}")
            raise