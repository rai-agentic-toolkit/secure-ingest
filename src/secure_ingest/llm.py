"""Secure LLM Delegation Pattern.

Provides a generic framework-level wrapper to ensure that only 
pre-validated payloads (ParseResult) are sent to underlying LLM SDKs
like OpenAI or Anthropic.

Design principles:
- Zero dependencies (no importing `openai` or `anthropic`)
- Intercepts generation methods
- Enforces a minimum taint level before sending
"""

from typing import Any, Callable
from .parser import ParseResult, TaintLevel

class SecurityException(Exception):
    """Raised when the LLM wrapper intercepts an unsafe or invalid payload."""
    pass

class SecureLLMWrapper:
    """
    A zero-dependency generic wrapper that intercepts calls to an underlying LLM client.
    
    This wrapper prevents raw strings or unverified payloads from reaching the AI,
    enforcing that only ParseResult objects meeting a minimum safety threshold
    are permitted.
    """
    
    def __init__(
        self, 
        client: Any, 
        generation_method: str = "generate", 
        min_taint: TaintLevel = TaintLevel.VALIDATED
    ):
        """
        Args:
            client: The underlying LLM client object (e.g., openai.chat.completions)
            generation_method: The name of the method to intercept (e.g., "create")
            min_taint: The minimum required TaintLevel for the payload to be passed through
        """
        self._client = client
        self._method_name = generation_method
        self._min_taint = min_taint
        
    def __getattr__(self, name: str) -> Any:
        """
        Intercept attribute access. If it's the generation method, wrap it.
        Otherwise, delegate directly to the underlying client.
        """
        if name == self._method_name:
            return self._secure_generate
        return getattr(self._client, name)
        
    def _secure_generate(self, prompt: Any = None, *args, **kwargs) -> Any:
        """
        The intercepted wrapper method. Checks the payload before calling the real method.
        """
        # Support passing prompt as either a positional or keyword argument
        # We assume the first positional argument is the prompt if provided,
        # or it's passed as a kwarg named "prompt", "messages", etc.
        
        # Check positional first
        if prompt is not None:
            payload = prompt
        else:
            # Fallback to common kwarg names for prompts when intercepting
            payload = kwargs.get("prompt") or kwargs.get("messages")
            if payload is None:
                raise SecurityException("Could not identify the payload in the method arguments.")
        
        # In a list of messages context (like OpenAI), we need to check if ANY of the messages
        # are ParseResults and enforce policy on them. For simplicity in the generic wrapper,
        # we expect the primary payload parameter (e.g. the single string prompt) to be the ParseResult.
        # If the user passes a list, this generic wrapper expects the user to have validated the entire list
        # or wrapped the individual string components. If the entire list isn't a ParseResult, we reject.
        
        if not isinstance(payload, ParseResult):
            raise SecurityException(
                f"LLM wrapper strictly requires a ParseResult. Received: {type(payload).__name__}. "
                "Raw strings or unvalidated objects are not permitted."
            )
            
        if payload.taint < self._min_taint:
            raise SecurityException(
                f"Payload rejected: Taint level {payload.taint} does not meet required {self._min_taint}."
            )
        
        # Extract the clean content
        clean_content = payload.content
        
        # Call the original method
        original_method = getattr(self._client, self._method_name)
        
        # If it was a generic keyword argument wrapper rather than positional
        if prompt is None:
            # Replace the keyword argument with the clean content
            if "prompt" in kwargs:
                kwargs["prompt"] = clean_content
            elif "messages" in kwargs:
                kwargs["messages"] = clean_content
            return original_method(*args, **kwargs)
        else:
            return original_method(clean_content, *args, **kwargs)
