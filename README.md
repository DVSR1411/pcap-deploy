# PCAP Analysis API - Deployment Package

## Files in this folder:

### Core Application Files:
- `app-deploy.py` - Flask API application (read-only, no PCAP upload)
- `elastic.py` - Elasticsearch client with authentication
- `aggregations.py` - Data aggregation functions
- `zeek_parser.py` - Zeek log parser
- `requirements-deploy.txt` - Python dependencies

### Docker Files:
- `Dockerfile` - Container image definition
- `docker-compose.yml` - Multi-container orchestration (Elasticsearch 8.13.0 + Kibana + API)
- `.dockerignore` - Files to exclude from Docker image

### Configuration:
- `.env.example` - Environment variables template
- `setup-security.sh` - Linux setup script for Elasticsearch security
- `setup-security.bat` - Windows setup script for Elasticsearch security

### Documentation:
- `DEPLOYMENT.md` - Deployment instructions
- `DEPLOYMENT_CHECKLIST.md` - Pre-deployment checklist
- `README.md` - This file

## Quick Start:

### 1. Copy to deployment system:
```bash
scp -r deployment/* user@server:/path/to/deployment/
```

### 2. On deployment system:
```bash
cd /path/to/deployment/

# Create .env file
cp .env.example .env
nano .env  # Set your password

# Ensure zeek_logs directory exists
mkdir -p zeek_logs

# Start services
docker-compose up -d

# Setup security (Linux)
chmod +x setup-security.sh
./setup-security.sh

# Add KIBANA_TOKEN to .env
nano .env

# Restart Kibana
docker restart kibana
```

### 3. Access:
- API: http://localhost:5000/api/health
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

## Requirements on Deployment System:
- Docker or Podman
- docker-compose or podman-compose
- zeek_logs directory with PCAP analysis data
- 4GB+ RAM (2GB for Elasticsearch)

## Security:
- Elasticsearch authentication enabled
- Passwords stored in .env (gitignored)
- Read-only mount for zeek_logs
- No PCAP upload capability (read-only API)

## Support:
See DEPLOYMENT.md and DEPLOYMENT_CHECKLIST.md for detailed instructions.
