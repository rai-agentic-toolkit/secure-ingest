import pytest
import dataclasses
from secure_ingest import parse, ContentType, TaintLevel
from secure_ingest.llm import SecureLLMWrapper, SecurityException

class DummyOpenAIClient:
    def __init__(self):
        pass
        
    def create(self, prompt: str, model="gpt-4"):
        return f"Response to: {prompt}"
        
class DummyAnthropicClient:
    def __init__(self):
        pass
        
    def complete(self, prompt: str, max_tokens=100):
        return f"Response to: {prompt}"

def test_secure_llm_wrapper_accepts_valid_payload():
    client = DummyOpenAIClient()
    secure_client = SecureLLMWrapper(client, generation_method="create", min_taint=TaintLevel.VALIDATED)
    
    # Simulate a valid payload
    parsed_payload = parse("hello world", ContentType.TEXT)
    parsed_payload = dataclasses.replace(parsed_payload, taint=TaintLevel.VALIDATED)
    
    # Should work and return the response
    response = secure_client.create(prompt=parsed_payload, model="gpt-4")
    assert response == "Response to: hello world"

def test_secure_llm_wrapper_rejects_raw_string():
    client = DummyOpenAIClient()
    secure_client = SecureLLMWrapper(client, generation_method="create", min_taint=TaintLevel.VALIDATED)
    
    # Wrap should raise an exception when given a raw string
    with pytest.raises(SecurityException, match="strictly requires a ParseResult"):
        secure_client.create(prompt="hello world")

def test_secure_llm_wrapper_rejects_untrusted_taint():
    client = DummyAnthropicClient()
    secure_client = SecureLLMWrapper(client, generation_method="complete", min_taint=TaintLevel.VALIDATED)
    
    # Simulate an untrusted payload
    parsed_payload = parse("hello world", ContentType.TEXT)
    parsed_payload = dataclasses.replace(parsed_payload, taint=TaintLevel.UNTRUSTED)
    
    # Wrap should raise an exception when taint level is too low
    with pytest.raises(SecurityException, match="Taint level TaintLevel.UNTRUSTED does not meet required TaintLevel.VALIDATED"):
        secure_client.complete(prompt=parsed_payload)

def test_secure_llm_wrapper_positional_args():
    client = DummyOpenAIClient()
    secure_client = SecureLLMWrapper(client, generation_method="create", min_taint=TaintLevel.VALIDATED)
    
    parsed_payload = parse("hello world", ContentType.TEXT)
    parsed_payload = dataclasses.replace(parsed_payload, taint=TaintLevel.VALIDATED)
    
    response = secure_client.create(parsed_payload, model="gpt-4")
    assert response == "Response to: hello world"
