# DonutSMP Stats API

A FastAPI-based REST API service that interfaces with DonutSMP Minecraft server to retrieve player statistics via an automated Minecraft client.

## Overview

This API provides programmatic access to DonutSMP player statistics through a connected Minecraft bot. It handles authentication, connection management, command execution, and response parsing.

## Authentication

### API Access
Protects all endpoints except `/health` and `/`. The API key is loaded from the environment variable specified in config (`STATS_API_KEY` by default).

### Minecraft Authentication
Uses Microsoft authentication via OAuth2/Xbox Live tokens. The session token (NOT an SSID) is obtained via the Microsoft OAuth flow and stored in the `MINECRAFT_SESSION_TOKEN` environment variable.

**Important:** The `MINECRAFT_SESSION_TOKEN` must be a valid Microsoft/Xbox access token, not a Mojang session server ID (SSID).

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy config example
cp config.example.json config.json
cp .env.example .env

# 3. Edit .env with your credentials
STATS_API_KEY=your_api_key_here
MINECRAFT_SESSION_TOKEN=your_microsoft_token_here
MC_USERNAME=your_minecraft_username

# 4. Run the API
python main.py
```

## API Usage

### Get Service Health
```bash
curl http://localhost:8000/health
```

### Get Player Stats
```bash
curl -H "X-API-Key: your_api_key" http://localhost:8000/stats/ExamplePlayer
```

### Get Connection Status
```bash
curl -H "X-API-Key: your_api_key" http://localhost:8000/connection
```

### Get Metrics
```bash
curl -H "X-API-Key: your_api_key" http://localhost:8000/metrics
```

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `minecraft.server_host` | Minecraft server hostname | `donutsmp.net` |
| `minecraft.server_port` | Minecraft server port | `25565` |
| `api.host` | API server bind address | `127.0.0.1` |
| `api.port` | API server port | `8000` |
| `api.request_timeout_seconds` | Stats request timeout | `30` |

## Error Codes

| Code | Description |
|------|-------------|
| `MINECRAFT_DISCONNECTED` | Client not connected to server |
| `INVALID_USERNAME` | Invalid Minecraft username format |
| `COMMAND_DENIED` | Server denied the stats command |
| `STATS_TIMEOUT` | No response within timeout |
| `UNSUPPORTED_INVENTORY` | Server returned unexpected format |
| `STATS_NOT_AVAILABLE` | Stats not found for player |

## Deployment (systemd)

```ini
[Unit]
Description=DonutSMP Stats API
After=network.target

[Service]
Type=simple
User=donutsmp
WorkingDirectory=/opt/donutsmp-stats-api
EnvironmentFile=/opt/donutsmp-stats-api/.env
ExecStart=/usr/bin/python3 /opt/donutsmp-stats-api/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Limitations

- **Protocol Support**: PyCraft (v0.7.0) supports up to Minecraft 1.19.4 (protocol 757). DonutSMP runs a newer protocol version.
- **Inventory Packets**: The published PyCraft build does NOT include container/window packets needed for full stats inventory parsing.
- **Stats Method**: Currently parses chat responses from `/stats` command. Full inventory support requires complete PyCraft or an alternative library.

## License

MIT
