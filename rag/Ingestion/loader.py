from pathlib import Path
from langchain_community.document_loaders import PyPDFLoader

from utils.logger import get_logger

logger=get_logger("loader","ingestion.log")

class DocumentLoader:
    def __init__(self,data_path="data/raw"):
        self.data_path=Path(data_path)
    def load_documents(self):
        documents=[]
        logger.info("Starting document ingestion")
        pdf_files=list(self.data_path.glob("*.pdf"))
        logger.info(f"Found {len(pdf_files)} PDF(s)")
        if not pdf_files:
            logger.warning("No PDF files found.")
            return documents
        for pdf in pdf_files:
            try:
                logger.info(f"Loading:{pdf.name}")
                loader=PyPDFLoader(str(pdf))
                docs=loader.load()
                documents.extend(docs)
                logger.info(f"{pdf.name}: Loaded {len(docs)} pages")
            except Exception as e:
                logger.exception(f"Failed to load {pdf.name}. Skipping file.")
        logger.info(f"Document ingestion completed. Loaded {len(documents)} pages.")

        return documents