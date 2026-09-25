# Cyber Agents Demo — Red Team vs Blue Team

An interactive cybersecurity simulation where LLM-powered agents attack and defend a virtual network, controllable from a live demo interface.

---

## Project Description

This project simulates a network intrusion scenario where autonomous AI agents play opposing roles:

- **Red Team** agents conduct reconnaissance, scanning, exploitation, lateral movement, and data exfiltration against a simulated target network.
- **Blue Team** agents monitor traffic, analyze threats, enforce firewall rules, respond to incidents, and gather threat intelligence in real time.

Two parallel stacks are provided:

| Stack | LLM Provider | Notes |
|---|---|---|
| Proprietary | Google Gemini (via Gemini API) | High capability, requires API key |
| Open Source | Groq + open-weight models (Llama 3, Mixtral) | Free tier available, fast inference |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                React Frontend (Vite)             │
│  Demo Control Panel │ Network Map │ Agent Logs   │
└───────────────────────────┬─────────────────────┘
                            │ REST / WebSocket
┌───────────────────────────▼─────────────────────┐
│              FastAPI Backend (Python)            │
│  Agent Orchestrator │ Scenario Engine │ WS Hub   │
├────────────────────────┬────────────────────────┤
│   Gemini Stack         │   Open Source Stack     │
│   google-generativeai  │   Groq SDK (llama3)     │
│   Red + Blue agents    │   Red + Blue agents     │
└────────────────────────┴────────────────────────┘
```

---

## Quick Start (Docker)

```bash
# Clone the repo
git clone https://github.com/your-org/cyber-agents-demo.git
cd cyber-agents-demo

# Copy and fill in environment variables
cp .env.example .env
# Edit .env with your API keys

# Start everything
docker-compose up --build
```

Frontend: http://localhost:5173
Backend API: http://localhost:8000
API docs: http://localhost:8000/docs

---

## Manual Setup

### Backend

```bash
cd cyber-agents-demo
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set environment variables
export GEMINI_API_KEY=your_key_here
export GROQ_API_KEY=your_key_here

uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
cp .env.example .env
# Edit .env: set VITE_API_URL=http://localhost:8000

npm install
npm run dev
```

---

## Deployment

### Backend — Render (free tier)

1. Create a new **Web Service** on https://render.com
2. Connect your GitHub repo, set root directory to `cyber-agents-demo/`
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add environment variables: `GEMINI_API_KEY`, `GROQ_API_KEY`
6. Note your service URL (e.g. `https://cyber-agents-demo.onrender.com`)

### Frontend — Vercel

1. Import project on https://vercel.com
2. Set root directory to `frontend/`
3. Framework: Vite (auto-detected)
4. Add environment variable: `VITE_API_URL` = your Render backend URL
5. Update `frontend/vercel.json` rewrites destination with your Render URL
6. Deploy

---

## How to Get Free API Keys

### Google Gemini (Proprietary Stack)
1. Go to https://aistudio.google.com/
2. Sign in with a Google account
3. Click **Get API key** → **Create API key**
4. Free tier: generous daily quota, no credit card required

### Groq (Open Source Stack)
1. Go to https://console.groq.com/
2. Create a free account
3. Navigate to **API Keys** → **Create API Key**
4. Free tier: rate-limited but sufficient for demos

---

## Scenario Description

### Network Topology

```
Internet ──► [Firewall] ──► [DMZ: Web Server 10.0.1.10]
                     │
                     └──► [Internal LAN 10.0.2.0/24]
                               ├── DB Server 10.0.2.20
                               ├── File Server 10.0.2.30
                               └── Admin Workstation 10.0.2.50
```

### Win Conditions

- **Red Team wins** if agents successfully exfiltrate data from the DB Server or Admin Workstation without being fully blocked.
- **Blue Team wins** if all attack attempts are detected and blocked before any data leaves the network.
- Partial outcomes (e.g., breach detected but contained) are scored on a point system visible in the demo UI.

---

## Agent Descriptions

### Red Team Agents

| Agent | Role | Techniques |
|---|---|---|
| **Recon** | Initial intelligence gathering | DNS enumeration, OSINT, port discovery |
| **Scanner** | Active network scanning | Nmap-style host/service discovery |
| **Exploit** | Vulnerability exploitation | CVE-based attacks on exposed services |
| **Pivot** | Lateral movement | Credential reuse, internal network traversal |
| **Exfil** | Data exfiltration | Staged data transfer to C2 server |

### Blue Team Agents

| Agent | Role | Techniques |
|---|---|---|
| **Monitor** | Traffic monitoring | Anomaly detection on network flows |
| **Analyzer** | Log and alert analysis | Correlation of events across hosts |
| **Firewall** | Dynamic rule enforcement | Automatic IP blocking, rate limiting |
| **Responder** | Incident response | Isolation, patching, credential rotation |
| **ThreatIntel** | Threat intelligence | IOC matching, attacker profiling |

---

## Screenshots

_Add demo screenshots here after first run._

---

## Tech Stack

**Frontend**
- React 18 + Vite
- Tailwind CSS
- WebSocket client (native)
- D3.js / React Flow (network visualization)

**Backend**
- Python 3.11+
- FastAPI + Uvicorn
- WebSocket server
- google-generativeai (Gemini)
- groq (Llama 3 / Mixtral via Groq API)
- asyncio for concurrent agent execution

**Infrastructure**
- Docker + docker-compose (local)
- Render (backend hosting)
- Vercel (frontend hosting)
