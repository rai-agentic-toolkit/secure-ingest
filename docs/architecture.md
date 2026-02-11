# System Architecture: Secure Agent Content Ingestion

## Overview

The Secure Agent Content Ingestion System implements a **layered defense architecture** that enables safe consumption of content from other agents without risk of prompt injection. The system follows the principle of **architectural constraints over prompt constraints**, making attacks structurally impossible rather than just detectable.

### Architectural Foundation & Attribution

This architecture synthesizes and implements security patterns established by leading AI security researchers:

- **Design patterns** from Beurer-Kellner et al. (arxiv:2506.08837), particularly the Dual LLM and Action-Selector patterns
- **Control flow integrity** principles from DeepMind's CaMeL framework (Debenedetti et al.)
- **OS-level security controls** from NVIDIA AI Red Team sandboxing guidance
- **Layered defense strategies** from Lakera's indirect prompt injection research

Our contribution is applying these proven principles to the specialized domain of agent-to-agent content ingestion.

## Core Architecture Principles

1. **Trust Boundary Enforcement**: Clear separation between trusted system operations and untrusted content processing
2. **Capability Isolation**: Parsers have no tools, memory, or network access
3. **Schema-First Validation**: All content must conform to predefined schemas or be discarded
4. **Semantic Anomaly Detection**: ML-based detection of injection-like patterns
5. **Layered Defense**: Multiple independent security mechanisms

## System Overview

```mermaid
graph TB
    subgraph "External Environment"
        A1[Security Agent]
        A2[Analysis Agent]
        A3[Research Agent]
    end

    subgraph "Secure Ingestion System"
        subgraph "Trust Boundary"
            IQ[Ingestion Queue]
            CP[Content Parser<br/>Stateless LLM]
            SV[Schema Validator]
            SAD[Semantic Anomaly Detector]
        end

        subgraph "Trusted Environment"
            DS[Data Store]
            API[Query API]
            AU[Audit Logger]
        end
    end

    subgraph "Consuming Applications"
        CA[Consumer Agent]
        DA[Dashboard App]
        RS[Reporting System]
    end

    A1 -->|Raw Content| IQ
    A2 -->|Raw Content| IQ  
    A3 -->|Raw Content| IQ

    IQ --> CP
    CP -->|Structured Data| SV
    SV -->|Valid Data| SAD
    SAD -->|Clean Data| DS

    DS --> API
    API --> CA
    API --> DA
    API --> RS

    CP -.->|Parse Events| AU
    SV -.->|Validation Events| AU
    SAD -.->|Detection Events| AU
```

## Detailed Component Architecture

### 1. Content Ingestion Layer

```mermaid
flowchart TD
    subgraph "Content Sources"
        AS[Agent Security Findings]
        AR[Agent Analysis Reports]
        AD[Agent Data Summaries]
        AM[Agent Metadata]
    end

    subgraph "Ingestion Pipeline"
        IQ[Ingestion Queue<br/>Redis/RabbitMQ]
        RT[Rate Limiter]
        PS[Pre-Sanitizer]
    end

    subgraph "Content Parser"
        CP[Stateless Parser LLM]
        NO_TOOLS[❌ No Tools]
        NO_MEM[❌ No Memory]
        NO_NET[❌ No Network]
        SCHEMA_OUT[✅ Schema Output Only]
    end

    AS --> IQ
    AR --> IQ
    AD --> IQ
    AM --> IQ

    IQ --> RT
    RT --> PS
    PS --> CP

    CP --- NO_TOOLS
    CP --- NO_MEM
    CP --- NO_NET
    CP --- SCHEMA_OUT

    CP -->|JSON Schema| SV[Schema Validator]
```

### 2. Validation and Security Layer

```mermaid
flowchart TD
    subgraph "Multi-Layer Validation"
        SV[Schema Validator]
        FV[Format Validator]
        BV[Business Logic Validator]
        SAD[Semantic Anomaly Detector]
    end

    subgraph "Security Checks"
        TI[Text Injection Scanner]
        BE[Behavioral Embedding Analysis]
        AL[Anomaly Likelihood Scorer]
    end

    subgraph "Decision Engine"
        DT[Decision Tree]
        ACCEPT[Accept & Store]
        QUARANTINE[Quarantine for Review]
        REJECT[Reject & Log]
    end

    CP[Content Parser] --> SV
    SV -->|Valid Schema| FV
    FV -->|Valid Format| BV  
    BV -->|Valid Logic| SAD

    SAD --> TI
    SAD --> BE
    SAD --> AL

    TI --> DT
    BE --> DT
    AL --> DT

    DT --> ACCEPT
    DT --> QUARANTINE  
    DT --> REJECT
```

### 3. Data Flow Security

```mermaid
sequenceDiagram
    participant EA as External Agent
    participant IQ as Ingestion Queue
    participant CP as Content Parser
    participant SV as Schema Validator  
    participant SAD as Anomaly Detector
    participant DS as Data Store
    participant CA as Consumer Agent
    participant AL as Audit Log

    Note over CP: Stateless, No Capabilities

    EA->>IQ: Submit content
    Note over IQ: Rate limiting, basic sanitization

    IQ->>CP: Raw content
    CP->>AL: Log parse attempt

    CP->>SV: Structured output (JSON)
    Note over SV: Schema validation only

    alt Schema Valid
        SV->>SAD: Valid structured data
        SAD->>AL: Log validation success

        alt Anomaly Score < Threshold
            SAD->>DS: Store clean data
            DS->>AL: Log storage
        else Anomaly Detected
            SAD->>AL: Log anomaly (quarantine)
        end
    else Schema Invalid
        SV->>AL: Log validation failure (discard)
    end

    CA->>DS: Query for data
    DS->>CA: Validated content only
```

## Trust Boundary Analysis

### Critical Trust Boundaries

```mermaid
graph LR
    subgraph "UNTRUSTED"
        UT1[External Agents]
        UT2[Raw Content]  
        UT3[Parsing Results]
    end

    subgraph "BOUNDARY ENFORCEMENT"
        TB1[Ingestion Queue]
        TB2[Schema Validation]
        TB3[Anomaly Detection]
    end

    subgraph "TRUSTED"
        T1[Validated Data]
        T2[System Operations]
        T3[Consumer APIs]
    end

    UT1 -.->|Cannot Directly Access| T1
    UT2 --> TB1
    TB1 --> TB2
    TB2 --> TB3
    TB3 --> T1

    T1 --> T2
    T2 --> T3
```

### Security Guarantees at Each Boundary

1. **Ingestion Boundary**
   - Rate limiting prevents DoS
   - Basic sanitization removes obvious attacks
   - Queueing provides isolation and auditing

2. **Parser Boundary**
   - Stateless LLM cannot be compromised persistently
   - No tool access prevents action execution
   - Schema enforcement limits output format

3. **Validation Boundary**
   - Strict schema compliance required
   - Semantic analysis detects injection patterns
   - Multi-layer validation catches edge cases

4. **Storage Boundary**
   - Only validated content enters trusted storage
   - Audit trail for all decisions
   - Access controls on stored data

## Component Specifications

### Stateless Content Parser

**Design Principles:**

- **No Persistent State**: Each parse operation is completely isolated
- **No Capabilities**: Cannot call tools, access network, or store data
- **Schema-Constrained Output**: Can only produce predefined JSON structures
- **Sandboxed Execution**: Runs in isolated compute environment

**Implementation Requirements:**

```yaml
parser:
  model: "fast-parsing-model"  # Optimized for structured output
  max_tokens: 2048
  temperature: 0.1            # Deterministic parsing
  capabilities: []            # No tools whatsoever
  memory: false              # Stateless operation
  network_access: false     # No external connections
  output_schema: "strict"    # Must conform to predefined schemas
```

### Schema Validator

**Supported Schemas:**

- Security findings (CVE, CVSS, recommendations)
- Analysis reports (structured insights, confidence scores)
- Data summaries (metrics, trends, key points)
- Metadata (timestamps, source attribution, versions)

**Validation Levels:**

1. **Structural**: JSON schema compliance
2. **Format**: Field format validation (dates, IDs, ranges)
3. **Business Logic**: Domain-specific rules and constraints
4. **Cross-Reference**: Consistency with existing data

### Semantic Anomaly Detector

**Detection Strategies:**

1. **Text Pattern Analysis**: Regex patterns for common injection techniques
2. **Embedding Similarity**: Compare to known injection attempts using sentence embeddings
3. **Behavioral Analysis**: Detect unusual instruction-like language in data fields
4. **Statistical Outliers**: Flag content with unusual linguistic properties

**ML Model Pipeline:**

```mermaid
flowchart LR
    subgraph "Feature Extraction"
        TE[Text Embeddings]
        LP[Linguistic Patterns]
        SS[Statistical Signals]
    end

    subgraph "Model Ensemble"
        BC[Binary Classifier]
        AR[Anomaly Ranker]
        ER[Embedding Retrieval]
    end

    subgraph "Decision Logic"
        WS[Weighted Score]
        TH[Threshold Check]
        CF[Confidence Flag]
    end

    INPUT[Parsed Content] --> TE
    INPUT --> LP
    INPUT --> SS

    TE --> BC
    LP --> AR
    SS --> ER

    BC --> WS
    AR --> WS
    ER --> WS

    WS --> TH
    TH --> CF
    CF --> OUTPUT[Accept/Quarantine/Reject]
```

## Performance Considerations

### Throughput Optimization

- **Parallel Processing**: Multiple parser instances for high-volume ingestion
- **Caching**: Schema validation results cached for repeated patterns  
- **Batching**: Process multiple similar content pieces together
- **Fast Models**: Optimized LLMs for parsing (vs. general reasoning)

### Latency Optimization

- **Streaming**: Process content as it arrives rather than batch processing
- **Early Rejection**: Fail fast on obvious invalid content
- **Optimistic Processing**: Begin downstream processing before full validation
- **Resource Pooling**: Pre-warmed parser instances

### Scalability Architecture

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[NGINX/HAProxy]
    end

    subgraph "Parser Pool"
        P1[Parser Instance 1]
        P2[Parser Instance 2]
        P3[Parser Instance N]
    end

    subgraph "Validation Service"
        VS[Validation Service]
        Cache[(Redis Cache)]
    end

    subgraph "Storage Layer"
        DS[(Database)]
        FS[(File Storage)]
    end

    LB --> P1
    LB --> P2
    LB --> P3

    P1 --> VS
    P2 --> VS
    P3 --> VS

    VS --> Cache
    VS --> DS
    VS --> FS
```

## Security Properties

### Formal Security Guarantees

1. **Isolation Guarantee**: Untrusted content cannot execute actions in the parsing environment
2. **Output Constraint**: Parser can only produce predefined structured formats
3. **State Independence**: Each parsing operation cannot influence future operations
4. **Capability Separation**: Validation logic runs separately from parsing logic

### Attack Resistance Properties

1. **Prompt Injection Immunity**: Parser has no tools to be hijacked
2. **Memory Poisoning Resistance**: Stateless operation prevents persistent compromise
3. **Exfiltration Prevention**: No network access from parsing environment
4. **Escalation Prevention**: Validated data cannot influence system operations

### Monitoring and Alerting

```mermaid
flowchart TD
    subgraph "Monitoring Points"
        MP1[Parse Success/Failure Rates]
        MP2[Schema Validation Rates]  
        MP3[Anomaly Detection Rates]
        MP4[Processing Latency]
        MP5[Queue Depth]
    end

    subgraph "Alert Conditions"
        AC1[High Failure Rate > 10%]
        AC2[Anomaly Rate Spike > 5%]
        AC3[Latency > SLA Threshold]
        AC4[Queue Backlog > 1000]
    end

    subgraph "Response Actions"
        RA1[Scale Parser Pool]
        RA2[Investigate Content Source]
        RA3[Adjust Validation Thresholds]
        RA4[Emergency Circuit Breaker]
    end

    MP1 --> AC1
    MP2 --> AC2
    MP3 --> AC2
    MP4 --> AC3
    MP5 --> AC4

    AC1 --> RA2
    AC2 --> RA3
    AC3 --> RA1
    AC4 --> RA4
```

This architecture provides **provable security guarantees** while maintaining **production-ready performance** for safe agent-to-agent content ingestion at scale.
