from langchain_text_splitters import RecursiveCharacterTextSplitter
from utils.logger import get_logger

logger = get_logger("splitter", "ingestion.log")


class DocumentSplitter:
    def __init__(self, chunk_size=500, chunk_overlap=100):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
            separators=["\n\n", "\n", ". ", " ", ""],
        )

    def split_documents(self,documents):
        """
        Split loaded documents into smaller chunks.
        Args: documents(lists) - list of LangChain document objects
        Returns: list - chunked document objects.
        """
        try:
            logger.info("Starting document splitting")
            if not documents:
                logger.warning("No documents recieved for splitting.")
                return []
            chunks=self.text_splitter.split_documents(documents)
            logger.info(
                f"Successfully created {len(chunks)} chunks "
                f"from {len(documents)} documents"
            )
            return chunks
        except Exception as e:
            logger.exception(f"Error while splitting documents: {e}")
            return []