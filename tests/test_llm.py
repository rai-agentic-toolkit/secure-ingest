import pytest
from secure_ingest import parse, ContentType, ValidatedPayload
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
    secure_client = SecureLLMWrapper(client, generation_method="create")
    
    # Simulate a valid payload
    parsed_payload = ValidatedPayload(content="hello world", content_type=ContentType.TEXT, chain_id="123")
    
    # Should work and return the response
    response = secure_client.create(prompt=parsed_payload, model="gpt-4")
    assert response == "Response to: hello world"

def test_secure_llm_wrapper_rejects_raw_string():
    client = DummyOpenAIClient()
    secure_client = SecureLLMWrapper(client, generation_method="create")
    
    # Wrap should raise an exception when given a raw string
    with pytest.raises(SecurityException, match="strictly requires a ValidatedPayload"):
        secure_client.create(prompt="hello world")

def test_secure_llm_wrapper_rejects_untrusted_parse_result():
    client = DummyAnthropicClient()
    secure_client = SecureLLMWrapper(client, generation_method="complete")
    
    # Simulate an untrusted payload
    parsed_payload = parse("hello world", ContentType.TEXT)
    
    # Wrap should raise an exception when given ParseResult
    with pytest.raises(SecurityException, match="strictly requires a ValidatedPayload"):
        secure_client.complete(prompt=parsed_payload)

def test_secure_llm_wrapper_positional_args():
    client = DummyOpenAIClient()
    secure_client = SecureLLMWrapper(client, generation_method="create")
    
    parsed_payload = ValidatedPayload(content="hello world", content_type=ContentType.TEXT, chain_id="123")
    
    response = secure_client.create(parsed_payload, model="gpt-4")
    assert response == "Response to: hello world"


def make_policy(**kwargs):
    from secure_ingest import StrictPolicy, ContentType
    opts = {
        'allowed_types': frozenset([ContentType.JSON, ContentType.TEXT, ContentType.MARKDOWN, ContentType.YAML, ContentType.XML]),
        'max_size_bytes': 100000,
        'max_depth': 50
    }
    if 'max_size' in kwargs:
        kwargs['max_size_bytes'] = kwargs.pop('max_size')
    if 'strip_injections' in kwargs:
        val = kwargs.pop('strip_injections')
        kwargs['mutation_mode'] = "REJECT" if val else "IGNORE"
    if 'deny_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('deny_rules')
    if 'allow_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('allow_rules')
    opts.update(kwargs)
    return StrictPolicy(**opts)


def make_policy(**kwargs):
    from secure_ingest import StrictPolicy, ContentType
    opts = {
        'allowed_types': frozenset([ContentType.JSON, ContentType.TEXT, ContentType.MARKDOWN, ContentType.YAML, ContentType.XML]),
        'max_size_bytes': 100000,
        'max_depth': 50
    }
    if 'max_size' in kwargs:
        kwargs['max_size_bytes'] = kwargs.pop('max_size')
    if 'strip_injections' in kwargs:
        val = kwargs.pop('strip_injections')
        kwargs['mutation_mode'] = "REJECT" if val else "IGNORE"
    if 'deny_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('deny_rules')
    if 'allow_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('allow_rules')
    opts.update(kwargs)
    return StrictPolicy(**opts)
