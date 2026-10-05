import re
from utils.logger import get_logger

logger=get_logger("query_sanitizer","query_sanitizer.log")

class QuerySanitizer:
    """
    Deterministic query validation and normalization.
    """
    def __init__(self):
        logger.info("Initializating QuerySanitizer...")
        logger.info("QuerySanitizer initialized successfully")

    def sanitize(self,query):
        """Validate and normalize a query"""
        changes=[]

        # 1. Input validation

        if not isinstance(query,str):
            logger.warning("Invalid query input type: %s",type(query).__name__)
            return{
                "original_query": query,
                "sanitized_query":"",
                "was_modified": False,
                "changes": ["invalid_input_type"],
                "is_valid": False
            }

        # 2. Empty input

        if not query.strip():
            logger.warning("Empty or whitespace-only query received")
            return{
                "original_query": query,
                "sanitized_query": "",
                "was_modified": query != "",
                "changes": (["empty_input"] if query!="" else []),
                "is_valid": False
            }

        # 3. Whitespace normalization

        sanitized_query=re.sub(r"\s+"," ",query.strip())
        if sanitized_query!=query:
            changes.append("whitespace_normalized")
            logger.info("Whitesapce normalization performed")

        # 4. Determine whether query was modiffied

        was_modified=sanitized_query!=query
        if was_modified:
            logger.info("Query sanitization completed with changes: %s",changes)
        else:
            logger.info("Query sanitization completed without changes")
        return{
            "original_query": query,
            "sanitized_query": sanitized_query,
            "was_modified": was_modified,
            "changes": changes,
            "is_valid": True
        }