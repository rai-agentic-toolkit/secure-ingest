# Implementation Guide: Secure Agent Content Ingestion System

## Overview

This guide provides step-by-step instructions for deploying and operating the Secure Agent Content Ingestion System in production environments. Follow this guide to establish a secure, scalable content ingestion pipeline.

## Prerequisites

### Infrastructure Requirements

```bash
# Minimum hardware requirements
CPU: 4+ cores (8+ recommended for production)
RAM: 8GB+ (16GB+ recommended)  
Storage: 100GB+ SSD
Network: 1Gbps+ connection

# Software requirements
OS: Ubuntu 20.04+ / CentOS 8+ / Container runtime
Python: 3.9+
Docker: 20.10+
Docker Compose: 2.0+
```

### Access Requirements

```bash
# API access for LLM services
export LLM_API_KEY="your-openai-or-anthropic-key"

# Database credentials
export DB_USER="secure_user"
export DB_PASSWORD="strong_random_password"
export DB_NAME="secure_ingest"

# Redis credentials  
export REDIS_PASSWORD="redis_auth_password"

# SSL certificates for production
# - /etc/ssl/certs/secure-ingest.crt
# - /etc/ssl/private/secure-ingest.key
```

## Phase 1: Environment Setup

### 1.1 System Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    docker.io \
    docker-compose \
    nginx \
    postgresql-client \
    redis-tools \
    curl \
    jq \
    htop

# Configure Docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

### 1.2 Directory Structure Setup

```bash
# Create project structure
mkdir -p ~/secure-ingest/{src,config,data,logs,schemas,models}
cd ~/secure-ingest

# Create required subdirectories
mkdir -p {config/nginx,data/postgres,data/redis,logs/{app,nginx},schemas/v1,models/ml}

# Set proper permissions
chmod 755 data/postgres data/redis logs/app logs/nginx
chmod 644 schemas/v1/*
```

### 1.3 Configuration Files

Create the main environment configuration:

```bash
# Create .env file
cat > .env << 'EOF'
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# LLM Configuration  
LLM_API_KEY=your_api_key_here
LLM_MODEL=gpt-3.5-turbo
LLM_MAX_TOKENS=2048
LLM_TEMPERATURE=0.1

# Database Configuration
DATABASE_URL=postgresql://secure_user:strong_password@postgres:5432/secure_ingest
POSTGRES_DB=secure_ingest
POSTGRES_USER=secure_user
POSTGRES_PASSWORD=strong_password

# Redis Configuration
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=redis_auth_password

# Security Configuration
JWT_SECRET=your_jwt_secret_key_here
RATE_LIMIT_PER_MINUTE=60
MAX_CONTENT_SIZE_MB=1

# Monitoring
PROMETHEUS_PORT=9090
LOG_LEVEL=INFO
EOF
```

## Phase 2: Core Services Deployment

### 2.1 Database Setup

Create PostgreSQL configuration:

```bash
# Create postgres init script
cat > config/postgres/init.sql << 'EOF'
-- Create secure_ingest database
CREATE DATABASE secure_ingest;

-- Create application user
CREATE USER secure_user WITH PASSWORD 'strong_password';
GRANT ALL PRIVILEGES ON DATABASE secure_ingest TO secure_user;

-- Connect to the database
\c secure_ingest;

-- Create audit log table
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    source_agent VARCHAR(100),
    content_type VARCHAR(50),
    submission_id VARCHAR(50),
    result VARCHAR(20),
    details JSONB,
    processing_time_ms INTEGER
);

-- Create content metadata table
CREATE TABLE content_metadata (
    content_id VARCHAR(50) PRIMARY KEY,
    source_agent VARCHAR(100) NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    validated_at TIMESTAMPTZ,
    anomaly_score DECIMAL(5,4),
    validation_details JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
);

-- Create indexes
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_content_metadata_source ON content_metadata(source_agent);
CREATE INDEX idx_content_metadata_type ON content_metadata(content_type);
CREATE INDEX idx_content_metadata_status ON content_metadata(status);

-- Grant permissions
GRANT ALL ON ALL TABLES IN SCHEMA public TO secure_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO secure_user;
EOF
```

### 2.2 Docker Compose Configuration

Create the main deployment configuration:

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'

networks:
  secure-ingest:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
  ml_models:

services:
  # Reverse proxy and load balancer
  nginx:
    image: nginx:1.21-alpine
    container_name: secure-ingest-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./logs/nginx:/var/log/nginx
      - /etc/ssl/certs:/etc/ssl/certs:ro
      - /etc/ssl/private:/etc/ssl/private:ro
    depends_on:
      - api-gateway
    networks:
      - secure-ingest
    restart: unless-stopped

  # Main API gateway
  api-gateway:
    build:
      context: ./src
      dockerfile: Dockerfile.gateway
    container_name: secure-ingest-gateway
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
      - LOG_LEVEL=${LOG_LEVEL}
    volumes:
      - ./logs/app:/app/logs
    depends_on:
      - postgres
      - redis
    networks:
      - secure-ingest
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'

  # Content parser service
  content-parser:
    build:
      context: ./src  
      dockerfile: Dockerfile.parser
    environment:
      - LLM_API_KEY=${LLM_API_KEY}
      - LLM_MODEL=${LLM_MODEL}
      - LLM_MAX_TOKENS=${LLM_MAX_TOKENS}
      - LLM_TEMPERATURE=${LLM_TEMPERATURE}
      - REDIS_URL=${REDIS_URL}
      - LOG_LEVEL=${LOG_LEVEL}
    volumes:
      - ./logs/app:/app/logs
    depends_on:
      - redis
    networks:
      - secure-ingest
    restart: unless-stopped
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 2G
          cpus: '1'

  # Schema validator service  
  schema-validator:
    build:
      context: ./src
      dockerfile: Dockerfile.validator
    environment:
      - REDIS_URL=${REDIS_URL}
      - LOG_LEVEL=${LOG_LEVEL}
    volumes:
      - ./schemas:/app/schemas:ro
      - ./logs/app:/app/logs
    depends_on:
      - redis
    networks:
      - secure-ingest
    restart: unless-stopped
    deploy:
      replicas: 2

  # Anomaly detector service
  anomaly-detector:
    build:
      context: ./src
      dockerfile: Dockerfile.detector  
    environment:
      - REDIS_URL=${REDIS_URL}
      - MODEL_PATH=/app/models
      - LOG_LEVEL=${LOG_LEVEL}
    volumes:
      - ml_models:/app/models
      - ./logs/app:/app/logs
    depends_on:
      - redis
    networks:
      - secure-ingest
    restart: unless-stopped
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 4G
          cpus: '2'

  # PostgreSQL database
  postgres:
    image: postgres:14-alpine
    container_name: secure-ingest-db
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}  
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./config/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - secure-ingest
    restart: unless-stopped
    command: [
      "postgres",
      "-c", "max_connections=200",
      "-c", "shared_buffers=256MB",
      "-c", "effective_cache_size=1GB"
    ]

  # Redis cache and message queue
  redis:
    image: redis:7-alpine
    container_name: secure-ingest-redis
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --appendonly yes
      --maxmemory 512mb
      --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - secure-ingest
    restart: unless-stopped

  # Prometheus monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: secure-ingest-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - secure-ingest
    restart: unless-stopped

EOF
```

### 2.3 NGINX Configuration

Create NGINX reverse proxy configuration:

```bash
cat > config/nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream api_gateway {
        server api-gateway:8000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=60r/m;
    limit_req_zone $binary_remote_addr zone=submit_limit:10m rate=10r/m;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/ssl/certs/secure-ingest.crt;
        ssl_certificate_key /etc/ssl/private/secure-ingest.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

        # API endpoints
        location /api/ {
            limit_req zone=api_limit burst=20 nodelay;
            proxy_pass http://api_gateway;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Content submission (stricter rate limit)
        location /api/v1/ingest {
            limit_req zone=submit_limit burst=5 nodelay;
            proxy_pass http://api_gateway;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Content size limit
            client_max_body_size 1M;
        }

        # Health checks (no rate limit)
        location /health {
            proxy_pass http://api_gateway;
            access_log off;
        }

        # Metrics endpoint (protected)
        location /metrics {
            allow 127.0.0.1;
            allow 10.0.0.0/8;
            deny all;
            proxy_pass http://api_gateway;
        }
    }
}
EOF
```

## Phase 3: Application Code Deployment

### 3.1 Schema Definitions

Create content schemas:

```bash
# Security finding schema
cat > schemas/v1/security_finding.json << 'EOF'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://secure-ingest.ai/schemas/security_finding.json",
  "title": "Security Finding",
  "type": "object",
  "required": ["vulnerability_id", "severity", "description", "recommendation"],
  "properties": {
    "vulnerability_id": {
      "type": "string",
      "pattern": "^(CVE-[0-9]{4}-[0-9]{4,}|CUSTOM-[A-Z0-9]{8})$"
    },
    "severity": {
      "type": "string",
      "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    },
    "cvss_score": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 10.0
    },
    "description": {
      "type": "string",
      "maxLength": 2000,
      "minLength": 10
    },
    "affected_systems": {
      "type": "array",
      "items": {"type": "string"},
      "maxItems": 20
    },
    "recommendation": {
      "type": "string",
      "maxLength": 1000,
      "minLength": 5
    }
  },
  "additionalProperties": false
}
EOF
```

### 3.2 Application Source Code Structure

```bash
# Create source code structure
mkdir -p src/{gateway,parser,validator,detector,common}

# Create requirements files for each service
cat > src/requirements-common.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
redis==5.0.1
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
prometheus-client==0.19.0
structlog==23.2.0
httpx==0.25.2
EOF

cat > src/requirements-parser.txt << 'EOF'
openai==1.3.8
anthropic==0.7.8
tiktoken==0.5.2
EOF

cat > src/requirements-detector.txt << 'EOF'
sentence-transformers==2.2.2
torch==2.1.2
scikit-learn==1.3.2
numpy==1.24.4
transformers==4.35.2
joblib==1.3.2
EOF
```

### 3.3 Docker Build Files

Create Dockerfiles for each service:

```bash
# Gateway Dockerfile
cat > src/Dockerfile.gateway << 'EOF'
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements-common.txt .
RUN pip install --no-cache-dir -r requirements-common.txt

# Copy application code
COPY gateway/ ./gateway/
COPY common/ ./common/

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start application
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# Parser Dockerfile
cat > src/Dockerfile.parser << 'EOF'
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements-common.txt requirements-parser.txt ./
RUN pip install --no-cache-dir -r requirements-common.txt -r requirements-parser.txt

# Copy code
COPY parser/ ./parser/
COPY common/ ./common/

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
RUN chown -R appuser:appuser /app
USER appuser

# Start parser service
CMD ["python", "-m", "parser.service"]
EOF
```

## Phase 4: Deployment and Testing

### 4.1 Initial Deployment

```bash
# Build and start services
docker-compose build
docker-compose up -d

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f api-gateway
docker-compose logs -f content-parser
```

### 4.2 Health Check Verification

```bash
# Test basic connectivity
curl http://localhost/health

# Expected response:
# {"status": "healthy", "timestamp": "2024-01-15T10:30:00.000Z"}

# Test detailed health check
curl http://localhost/health/detailed

# Test metrics endpoint (from allowed IP)
curl http://localhost/metrics
```

### 4.3 Functional Testing

Create a test script:

```bash
cat > test_deployment.sh << 'EOF'
#!/bin/bash

API_BASE="http://localhost/api/v1"
AUTH_TOKEN="test_agent_token"

echo "Testing content submission..."

# Test valid content submission
RESPONSE=$(curl -s -X POST \
  "${API_BASE}/ingest" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "source_agent_id": "test-agent",
    "content_type": "security_finding",
    "content": {
      "vulnerability_id": "CVE-2024-0001",
      "severity": "HIGH",
      "description": "SQL injection vulnerability in authentication system",
      "recommendation": "Apply security patches immediately"
    }
  }')

echo "Submission response: $RESPONSE"

# Extract submission ID
SUBMISSION_ID=$(echo $RESPONSE | jq -r '.submission_id')

if [ "$SUBMISSION_ID" != "null" ]; then
  echo "Checking processing status..."
  sleep 2

  STATUS_RESPONSE=$(curl -s \
    "${API_BASE}/status/${SUBMISSION_ID}" \
    -H "Authorization: Bearer ${AUTH_TOKEN}")

  echo "Status response: $STATUS_RESPONSE"
else
  echo "ERROR: No submission ID received"
  exit 1
fi

echo "Testing query API..."
QUERY_RESPONSE=$(curl -s \
  "${API_BASE}/content?type=security_finding&limit=10" \
  -H "Authorization: Bearer ${AUTH_TOKEN}")

echo "Query response: $QUERY_RESPONSE"

echo "Deployment test completed successfully!"
EOF

chmod +x test_deployment.sh
./test_deployment.sh
```

## Phase 5: Production Hardening

### 5.1 Security Configuration

```bash
# Create SSL certificates (using Let's Encrypt)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com

# Configure firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp  
sudo ufw allow 443/tcp
sudo ufw --force enable

# Set up log rotation
sudo cat > /etc/logrotate.d/secure-ingest << 'EOF'
/home/user/secure-ingest/logs/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
```

### 5.2 Monitoring Setup

```bash
# Prometheus configuration
cat > config/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'secure-ingest'
    static_configs:
      - targets: ['api-gateway:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

# Create alerting rules
cat > config/prometheus/alert_rules.yml << 'EOF'
groups:
  - name: secure-ingest-alerts
    rules:
      - alert: HighErrorRate
        expr: rate(content_submissions_total{result="error"}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"

      - alert: AnomalySpike
        expr: rate(content_submissions_total{result="anomaly"}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Anomaly detection spike"

      - alert: ServiceDown
        expr: up{job="secure-ingest"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
EOF
```

### 5.3 Backup Configuration

```bash
# Create backup script
cat > backup_system.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/backup/secure-ingest"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p ${BACKUP_DIR}/${DATE}

# Backup database
docker-compose exec -T postgres pg_dump \
  -U secure_user secure_ingest \
  > ${BACKUP_DIR}/${DATE}/database.sql

# Backup Redis data
docker-compose exec -T redis redis-cli \
  --rdb /data/dump.rdb
docker cp secure-ingest-redis:/data/dump.rdb \
  ${BACKUP_DIR}/${DATE}/redis.rdb

# Backup configuration
cp -r config/ ${BACKUP_DIR}/${DATE}/config/
cp -r schemas/ ${BACKUP_DIR}/${DATE}/schemas/

# Compress backup
tar -czf ${BACKUP_DIR}/backup_${DATE}.tar.gz \
  -C ${BACKUP_DIR}/${DATE} .

# Clean up old backups (keep 30 days)
find ${BACKUP_DIR} -name "backup_*.tar.gz" \
  -mtime +30 -delete

echo "Backup completed: backup_${DATE}.tar.gz"
EOF

chmod +x backup_system.sh

# Schedule backups
(crontab -l 2>/dev/null; echo "0 2 * * * $PWD/backup_system.sh") | crontab -
```

## Phase 6: Operational Procedures

### 6.1 Scaling Operations

```bash
# Scale parser services
docker-compose up -d --scale content-parser=5

# Check service status
docker-compose ps content-parser

# Monitor resource usage
docker stats --no-stream
```

### 6.2 Log Analysis

```bash
# View recent errors
grep "ERROR" logs/app/*.log | tail -20

# Monitor anomaly detection
grep "anomaly_detected" logs/app/*.log | tail -10

# Check rate limiting
grep "rate_limit" logs/nginx/access.log | tail -20

# Performance analysis
grep "processing_time" logs/app/*.log | \
  awk '{print $NF}' | \
  sort -n | tail -10
```

### 6.3 Incident Response Procedures

```bash
# Emergency circuit breaker activation
cat > emergency_stop.sh << 'EOF'
#!/bin/bash
echo "EMERGENCY STOP: Pausing all content processing"

# Stop content ingestion
docker-compose stop content-parser schema-validator anomaly-detector

# Block all ingestion endpoints at nginx level
docker-compose exec nginx nginx -s reload

echo "System stopped. Investigate and run emergency_resume.sh when safe."
EOF

# Emergency resume
cat > emergency_resume.sh << 'EOF'
#!/bin/bash
echo "RESUMING: Restarting content processing services"

# Restart services
docker-compose start content-parser schema-validator anomaly-detector

# Restore nginx configuration
docker-compose exec nginx nginx -s reload

echo "System resumed. Monitor logs closely."
EOF

chmod +x emergency_stop.sh emergency_resume.sh
```

### 6.4 Maintenance Procedures

```bash
# Rolling update procedure
cat > rolling_update.sh << 'EOF'
#!/bin/bash

echo "Starting rolling update..."

# Build new images
docker-compose build

# Update services one by one
services=("content-parser" "schema-validator" "anomaly-detector" "api-gateway")

for service in "${services[@]}"; do
  echo "Updating ${service}..."
  docker-compose up -d --no-deps ${service}

  # Wait for health check
  sleep 30

  # Verify health
  if ! curl -f http://localhost/health; then
    echo "ERROR: Health check failed for ${service}"
    exit 1
  fi

  echo "${service} updated successfully"
done

echo "Rolling update completed successfully"
EOF

chmod +x rolling_update.sh
```

## Performance Tuning

### Resource Optimization

```yaml
# Add to docker-compose.yml for production tuning
services:
  content-parser:
    deploy:
      resources:
        reservations:
          memory: 1G
          cpus: '0.5'
        limits:
          memory: 2G
          cpus: '1'
    ulimits:
      nofile: 65536
    environment:
      - PYTHONOPTIMIZE=1
      - PYTHONDONTWRITEBYTECODE=1

  postgres:
    environment:
      - POSTGRES_SHARED_PRELOAD_LIBRARIES=pg_stat_statements
    command: [
      "postgres",
      "-c", "max_connections=200",
      "-c", "shared_buffers=512MB",
      "-c", "effective_cache_size=2GB",
      "-c", "work_mem=16MB",
      "-c", "maintenance_work_mem=256MB"
    ]
```

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. High Memory Usage

```bash
# Check memory usage per service
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Solution: Scale down or increase memory limits
docker-compose up -d --scale content-parser=2
```

#### 2. Database Connection Issues

```bash
# Check database connectivity
docker-compose exec api-gateway python -c "
import psycopg2
conn = psycopg2.connect('${DATABASE_URL}')
print('Database connection: OK')
"

# Check connection pool
grep "connection" logs/app/*.log | tail -20
```

#### 3. Anomaly Detection Overload

```bash
# Check anomaly detection performance
grep "anomaly_analysis_time" logs/app/*.log | \
  awk '{print $(NF-1)}' | sort -n | tail -10

# Temporary bypass (emergency only)
docker-compose exec redis redis-cli set emergency_bypass_anomaly true
```

This implementation guide provides everything needed to deploy and operate the Secure Agent Content Ingestion System in production environments with proper security, monitoring, and operational procedures.
