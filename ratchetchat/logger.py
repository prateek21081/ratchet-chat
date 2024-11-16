import logging

def log(key: bytes, plaintext: bytes, ciphertext: bytes, message: str):
    logger.info(f"Operation: {message} Key: {key.hex()} Plaintext: {plaintext.decode('utf-8', errors='ignore')} Ciphertext: {ciphertext.hex()}")

logging.basicConfig(filename="../logs/chat_log.txt", format='%(asctime)s %(message)s', filemode='w', level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info("This is a log message")
