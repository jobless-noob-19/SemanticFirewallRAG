from langchain_ollama import OllamaEmbeddings
from utils.logger import get_logger
logger=get_logger("embedding_service","embeddings.log")

class EmbeddingService:
    def __init__(self,model="nomic-embed-text"):
        self.model=model
        logger.info(f"Loading embedding model: {self.model}")
        self.embedding_model=OllamaEmbeddings(model=self.model)
        logger.info("Embedding model loaded successfully")

    def get_embedding_model(self):
        return self.embedding_model