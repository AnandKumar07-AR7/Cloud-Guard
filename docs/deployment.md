# CloudGuard — Deployment Guide

## 1. Overview
CloudGuard is packaged for containerized deployment via Docker Compose or standalone bare-metal / VM environments. The production architecture consists of three core services:
1. **PostgreSQL 16**: Relational persistence and audit chain storage.
2. **FastAPI Backend**: Core detection, risk, remediation, and API gateway engine.
3. **React Obsidian Command Center**: Production single-page application served via Nginx.

---

## 2. Docker Compose Deployment (Recommended)

### 2.1 Prerequisites
- Docker Engine 24.0+
- Docker Compose v2.20+
- 4 GB RAM minimum, 10 GB disk space

### 2.2 Quickstart
1. Clone the repository and navigate to the project root:
   ```bash
   git clone https://github.com/organization/cloudguard.git
   cd cloudguard
   ```

2. Generate an environment configuration from the template:
   ```bash
   cp .env.example .env
   ```
   Modify `.env` to configure your `JWT_SECRET_KEY` and deployment preferences:
   ```bash
   # Generate a 32-byte cryptographically secure secret
   openssl rand -hex 32
   ```

3. Launch the containerized stack:
   ```bash
   docker compose up -d
   ```

4. Verify service health and container status:
   ```bash
   docker compose ps
   ```

5. Access the Obsidian Command Center:
   - **Frontend UI (Canonical HTTPS)**: `https://localhost` (Port 443)
   - **HTTP Redirection**: `http://localhost` (Port 80 permanently redirects to HTTPS via 301)
   - **Backend API (Reverse Proxied)**: `https://localhost/api`
   - **Health Check**: `https://localhost/health`

---

## 3. Production Environment Configuration

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `CLOUDGUARD_MODE` | String | `demo` | Operating mode: `demo` (offline) or `aws` (live AWS). |
| `DATABASE_URL` | URI | — | PostgreSQL connection string. |
| `JWT_SECRET_KEY` | String | — | Minimum 32-character secret for signing access tokens. |
| `JWT_ALGORITHM` | String | `HS256` | JWT signing algorithm. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Int | `30` | Access token lifespan in minutes. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Int | `7` | Refresh token lifespan in days. |
| `AI_PROVIDER` | String | `demo` | `demo` (deterministic mock) or `anthropic` (live Claude API). |
| `ANTHROPIC_API_KEY` | String | — | Required only if `AI_PROVIDER=anthropic`. |
| `AWS_ACCESS_KEY_ID` | String | — | Required only if `CLOUDGUARD_MODE=aws`. |
| `AWS_SECRET_ACCESS_KEY` | String | — | Required only if `CLOUDGUARD_MODE=aws`. |
| `AWS_DEFAULT_REGION` | String | `us-east-1` | Primary AWS region to scan. |

---

## 4. Standalone Bare-Metal / Local Development Setup

### 4.1 Backend
1. Create a Python 3.11 virtual environment:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Apply database migrations:
   ```bash
   python -m alembic upgrade head
   ```
3. Run FastAPI backend:
   ```bash
   python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```

### 4.2 Frontend
1. Install Node.js dependencies:
   ```bash
   cd frontend
   npm install
   ```
2. Start the Vite development server:
   ```bash
   npm run dev
   ```
3. Build production bundle:
   ```bash
   npm run build
   ```
