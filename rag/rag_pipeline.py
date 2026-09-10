from utils.logger import get_logger
from rag.retriever import Retriever
from rag.generator import Generator

logger=get_logger("rag_pipeline","rag_pipeline.log");

class RAGPipeline:
    """
    Main RAG pipeline.
    """
    def __init__(self):
        """
        Initialize the RAG pipeline.
        Args:
            top_k: Number of relevant document chunks to retrieve.
        """
        logger.info("Initializing RAG Pipeline...")
        self.retriever=Retriever()
        self.generator=Generator()

        logger.info(f"RAG Pipeline initialized successfully ")

    def run(self, query: str) -> str:
        """
        Run the complete RAG pipeline.
        Args:
            query: User's question.
            
        Returns:
            Generated response from the LLM.
        """
        if not query or not query.strip():
            logger.warning("Empty query received.")
            return "Please provide a valid question."

        logger.info(f"Processing query: {query}")

        try:
            #Step 1: Retrieving 
            logger.info("Retrieving relevant documents...")

            documents=self.retriever.retrieve(query)

            if not documents:
                logger.warning("No relevant documents found.")

                return(
                    "I could not find relevant information in the"
                    "knowledge base to answer your question."
                )
            
            logger.info(f"Retrieved {len(documents)} relevant document chunks.")

            # Step 2: Build context

            context="\n\n".join(document.page_content for document in documents)

            # Step 3: Generate response using retrieved context
            logger.info("Sending retrieved context to generator...")

            response=self.generator.generate(query=query, context=context)

            logger.info("RAG Pipeline completed successfully.")

            return response

        except Exception:
            logger.exception("Error occured while while running RAG Pipeline.")
            raise