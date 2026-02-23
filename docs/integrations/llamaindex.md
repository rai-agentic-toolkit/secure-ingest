# LlamaIndex Integration Recipe

## The Problem
When ingesting thousands of documents into a vector database (RAG architectures), LlamaIndex data connectors blindly index external data. If an adversary introduces a malicious payload or a multi-megabyte string into your document corpus, you will waste expensive embedding tokens indexing garbage, or worse, poison the semantic retrieval boundaries of your agent.

## The Architecture
`secure-ingest` is inserted into the LlamaIndex `IngestionPipeline` as a custom Transformation node. Before a document is chunked and embedded, it passes through the `SecureDocumentScanner`, which structurally validates and enforces strict byte limits on the raw text.

## The Recipe

```python
from llama_index.core.schema import Document
from llama_index.core.ingestion import IngestionPipeline
from llama_index.core.node_parser import SimpleNodeParser
from llama_index.embeddings.openai import OpenAIEmbedding
from secure_ingest import parse, ContentType, ParseError, StrictPolicy

# Define the structural boundary policy for all ingested documents
document_defense_policy = StrictPolicy(
    allowed_types=frozenset({ContentType.TEXT, ContentType.MARKDOWN}),
    max_size_bytes=1024 * 500  # Max 500 KB per document chunk
)

class SecureDocumentScanner:
    """A LlamaIndex custom Transformation node that drops invalid documents."""

    def __call__(self, documents: list[Document], **kwargs) -> list[Document]:
        validated_docs = []

        for doc in documents:
            try:
                # 1. Parse and validate the document text
                result = parse(
                    content=doc.text,
                    content_type=ContentType.TEXT,
                    policy=document_defense_policy,
                    provenance=doc.metadata.get("source", "unknown_document")
                )

                # 2. Update the document with safely structured and limited output
                doc.text = result.content
                validated_docs.append(doc)

            except ParseError as e:
                # 3. Message is unsafe or too large. Drop the document from the pipeline.
                print(f"SECURITY WARNING: Dropped document [{doc.id_}] - {str(e)}")
                # We simply do not append to 'validated_docs', removing it from the ingestion loop.

        return validated_docs

# -----------------
# Setup LlamaIndex Pipeline
# -----------------
documents = [...] # Loaded from a SimpleDirectoryReader or WebReader

# 4. Inject SecureDocumentScanner into the pipeline before embedding
pipeline = IngestionPipeline(
    transformations=[
        SecureDocumentScanner(),         # Intercept and validate first
        SimpleNodeParser.from_defaults(),# Then chunk into nodes
        OpenAIEmbedding(),               # Finally embed safe nodes
    ]
)

# 5. Run the pipeline—only safe documents make it to the vector store
nodes = pipeline.run(documents=documents)
```

## The Escape Hatch
By implementing the transformation as a document filter, `secure-ingest` operates completely silently in the background.

When a `ParseError` occurs (e.g., an abnormally large document or an unexpected JSON structure masquerading as TEXT), the custom transformer simply **omits** the document from the list it returns. LlamaIndex smoothly continues embedding the remaining valid documents, saving money on chunking/embedding tokens and fully isolating the vector database from the structural anomaly.
