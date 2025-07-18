"""
Custom Exceptions cho AML Hybrid Scoring System
"""

class AMLProcessingError(Exception):
    """Base exception cho AML processing errors"""
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}

class DataProcessingError(AMLProcessingError):
    """Exception cho data processing errors"""
    pass

class RuleScoringError(AMLProcessingError):
    """Exception cho rule-based scoring errors"""
    pass

class BedrockError(AMLProcessingError):
    """Exception cho Bedrock API errors - non-critical"""
    pass

class ReconciliationError(AMLProcessingError):
    """Exception cho score reconciliation errors"""
    pass

class ConfigurationError(AMLProcessingError):
    """Exception cho configuration errors"""
    pass

class ValidationError(AMLProcessingError):
    """Exception cho data validation errors"""
    pass