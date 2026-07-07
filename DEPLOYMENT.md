# PCAP Analysis API - Deployment Guide

## Security Setup

### 1. Set Elasticsearch Password

Create a `.env` file:
```bash
cp .env.example .env
```

Edit `.env` and set a strong password:
```
ELASTIC_PASSWORD=your_strong_password_here
```

### 2. Deploy with Docker/Podman

```bash
# Using Docker
docker-compose up -d

# Using Podman
podman-compose up -d
```

### 3. Verify Deployment

```bash
# Check services are running
docker-compose ps

# Check API health
curl http://localhost:5000/api/health

# Check Elasticsearch (requires auth)
curl -u elastic:your_password http://localhost:9200
```

## Access Points

- **API**: http://localhost:5000
- **Kibana**: http://localhost:5601 (login: elastic / your_password)
- **Elasticsearch**: http://localhost:9200 (requires auth)

## Required Files on Deployment System

- Dockerfile
- docker-compose.yml
- app-deploy.py
- elastic.py
- aggregations.py
- zeek_parser.py
- requirements-deploy.txt
- .env (with your password)
- zeek_logs/ (directory with your PCAP analysis data)

## Zeek Logs Structure

```
zeek_logs/
├── <pcap_id_1>/
│   ├── conn.log
│   ├── dns.log
│   └── ...
└── <pcap_id_2>/
    └── ...
```

## Security Notes

✅ Elasticsearch authentication enabled
✅ Read-only mount for zeek_logs
✅ Password stored in .env (not in git)
✅ Network isolated to docker network

## Troubleshooting

```bash
# View logs
docker-compose logs -f pcap-api

# Restart services
docker-compose restart

# Rebuild after code changes
docker-compose up -d --build
```
