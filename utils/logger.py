import logging
import os
LOG_DIR="logs"
os.makedirs(LOG_DIR, exist_ok=True)
def get_logger(name,filename):
    logger=logging.getLogger(name)

    #Prevents duplicate hnadlers
    # Prevent adding handlers multiple times
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    formatter=logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    # Writes logs to a file
    file_handler=logging.FileHandler(os.path.join(LOG_DIR, filename),encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    #Displays logs in terminal
    console_handler=logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    #Add both handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger