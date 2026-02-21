from abc import ABC, abstractmethod
from typing import List


class BaseSemanticScanner(ABC):
    """
    Abstract Base Class for pluggable semantic scanners.
    
    Implementations can use local ONNX models, external APIs, etc., 
    to evaluate the intent of the payload, beyond just pattern matching.
    """
    @abstractmethod
    def scan(self, text: str) -> List[str]:
        """
        Scan the text for semantic violations.
        
        Args:
            text: The text payload to evaluate.
            
        Returns:
            A list of strings representing the names or descriptions of any
            semantic violations found. Return an empty list if the text is safe.
        """
        pass
