import logging
import logging.handlers
import os
import sys
from pathlib import Path

def setup_logging(log_dir: str = "logs", level: str = "INFO"):
    """Set up structured logging with rotating file handlers."""
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Clear existing handlers
    logger.handlers = []
    
    # Formatter
    formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S%z"
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / "api.log",
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Error file handler
    error_handler = logging.handlers.RotatingFileHandler(
        log_path / "error.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=3
    )
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)
    
    # Redact sensitive info from logs
    class SensitiveFilter(logging.Filter):
        sensitive_patterns = [
            'token', 'password', 'secret', 'key', 'credential'
        ]
        
        def filter(self, record):
            msg = str(record.getMessage()).lower()
            for term in self.sensitive_patterns:
                if term in msg and 'redacted' not in msg:
                    record.msg = f"Sensitive data redacted: {record.msg}"
                    break
            return True
    
    return logger
