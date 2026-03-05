"""
Logger Utility Module
Provides logging functionality for the SPTT
"""

import logging
import sys
from datetime import datetime
from pathlib import Path


def setup_logger(name: str = 'SPTT', 
                 level: int = logging.INFO,
                 log_file: str = None) -> logging.Logger:
    """
    Set up and configure a logger.
    
    Args:
        name: Logger name
        level: Logging level
        log_file: Optional file path to save logs
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = 'SPTT') -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        return setup_logger(name)
    
    return logger


class AuditLogger:
    """
    Audit logger for tracking security testing activities.
    """
    
    def __init__(self, log_file: str = 'reports/audit.log'):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
        """
        self.log_file = log_file
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    
    def log_action(self, action: str, details: dict):
        """
        Log an action with details.
        
        Args:
            action: Action description
            details: Dictionary of details
        """
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'action': action,
            'details': details
        }
        
        # Write to file
        with open(self.log_file, 'a') as f:
            f.write(f"{log_entry}\n")
    
    def log_scan(self, target: str, scan_type: str, results: dict):
        """Log a port scan action."""
        self.log_action('PORT_SCAN', {
            'target': target,
            'scan_type': scan_type,
            'results': results
        })
    
    def log_hash_crack(self, algorithm: str, success: bool, attempts: int):
        """Log a hash crack attempt."""
        self.log_action('HASH_CRACK', {
            'algorithm': algorithm,
            'success': success,
            'attempts': attempts
        })
    
    def log_brute_force(self, target: str, success: bool, attempts: int):
        """Log a brute force attempt."""
        self.log_action('BRUTE_FORCE', {
            'target': target,
            'success': success,
            'attempts': attempts
        })
