from pathlib import Path
from typing import List
from langchain_core.documents import Document 
from langchain_chroma import Chroma
from embeddings.embedding_service import EmbeddingService
from utils.logger import get_logger

logger=get_logger("chroma_manager","chroma_manager.log")

class ChromaManager:
    """
    Handles creation, loadingm updatingm and querying of the persistant Chroma vector database
    """

    def __init__(self, persist_directory:str = "vector_db/chroma_db"):
        self.persist_directory=Path(persist_directory)

        self.embedding_service=EmbeddingService()
        self.embedding_model=self.embedding_service.get_embedding_model()

        self.db=None

    def create_database(self,documents, batch_size=100):
        """
        Creates a new persistent Chroma database.
        """

        logger.info("Creating Chroma database...")
        logger.info(f"Total chunks to add: {len(documents)}")

        self.db=Chroma(
            collection_name="semantic_firewall",
            embedding_function=self.embedding_model,
            persist_directory=str(self.persist_directory),
        )
        total_documents=len(documents)
        for start in range(0,total_documents, batch_size):
            end=min(start+batch_size, total_documents)
            batch=documents[start:end]
            logger.info(
                f"Embedding and adding chunks {start+1}-{end} "
                f"of {total_documents}"
            )

            try:
                self.db.add_documents(batch)
                logger.info(
                    f"Successfully added chunks {start+1}-{end}"
                )
            except Exception:
                logger.exception(
                    f"Failed while processing chunks {start+1}-{end}"
                )
                raise
        logger.info(f"Database created successfully with {len(documents)} chunks.")
        return self.db

    def load_database(self):
        """Loads an existing """
        logger.info("Loading Chroma database...")
        self.db=Chroma(
            persist_directory=str(self.persist_directory),
            embedding_function=self.embedding_model,
            )
        logger.info("Database loaaded successfully.")
        return self.db

    def add_documents(self,documents:List[Document]):
        """Adds new documents to an existing databse."""
        if self.db is None:
            self.load_database()
        logger.info(f"Adding {len(documents)} new chunks...")
        self.db.add_documents(documents)
        logger.info("Documents added successfully.")

    def similarity_search(self,query: str, k: int=5):
        """Return the top-k most similar documents."""
        if self.db is None:
            self.load_database()
        logger.info(f"Running similarity search: {query}")
        return self.db.similarity_search(query,k=k)
    
    def get_retriever(self,k: int=5):
        """Returns a LangChain retriever."""
        if self.db is None:
            self.load_database()
        return self.db.as_retriever(
            search_kwargs={"k":k}
        )
    