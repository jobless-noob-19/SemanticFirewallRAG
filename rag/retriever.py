from typing import Any
from langchain_core.documents import Document
from vector_db.chroma_manager import ChromaManager
from utils.logger import get_logger

logger=get_logger("retriever","retriever.log")

class Retriever:
    """ Handles semantic retrieval of relevant documents chunks from the persistant vector database."""

    def __init__(
        self,
        persist_directory: str="vector_db/chroma_db",
        top_k: int=5
    ):
        self.top_k=top_k
        logger.info("Initializing Retriever...")

        self.chroma_manager=ChromaManager(persist_directory=persist_directory)

        # Load the existing Chroma database
        self.chroma_manager.load_database()

        logger.info(f"Retriever initialized successfully | top_k={self.top_k}")

    def retrieve(self,query:str)->list[Document]:
        """
        Retrieve the top-k most relevant document chunks.
        Args:
            query:user's Query
        """
        if not query or not query.strip():
            logger.warning("Empty query received.")
            return[]

        logger.info(f"Retrieving documents for query: {query}")

        try:
            documents=self.chroma_manager.similarity_search(query=query,k=self.top_k)
            logger.info(f"Successfully retrieved {len(documents)} documents.")
            return documents
        
        except Exception:
            logger.exception("Error occured during document retrieval.")
            raise

    def retrieve_with_metadata(
            self, query: str
    ) -> list[dict[str,Any]]:
        """
        Retrieve documents along with their metadata.
        Args: 
            query: User's query.
        Returns:
            List containing document content and metadata.
        """

        documents=self.retrieve(query)
        results=[]
        for document in documents:
            results.append(
                {
                    "content": document.page_content,
                    "metadata": document.metadata
                }
            )
        return results

    def get_langchain_retriever(self):
        """Return the underlying LangChain retriever."""

        logger.info(f"Creating LangChain retriever with top_k={self.top_k}")

        return self.chroma_manager.get_retriever(k=self.top_k)