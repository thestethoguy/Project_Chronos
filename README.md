# 🛡️ Project Chronos: AI-Driven Cyber Resilience Digital Twin

**Live Dashboard:** [https://project-chronos-beryl.vercel.app](https://project-chronos-beryl.vercel.app)

**Live API Endpoint:** [https://project-chronos-cxog.onrender.com](https://project-chronos-cxog.onrender.com)

An autonomous, real-time cyberattack simulation and incident response infrastructure monitoring dashboard. Project Chronos maps visual multi-stage attacks and executes active containment strategies without relying on rigid, pre-programmed rules.

Built by **The Ron's** (Priyam Prakash, Ashish, and Aman Aaryan).

---

## 🚀 Core Architecture Highlights

*   **Multi-Agent GenAI Orchestrator:** Powered by **CrewAI** and **Groq** using the highly optimized `llama-3.3-70b-versatile` endpoint. A Red Agent plans multi-stage lateral movements, while a Blue Agent determines active remediation techniques based on the MITRE ATT&CK framework.
*   **Serverless Graph Topology:** Structured utilizing a **Neo4j AuraDB** cloud relational architecture to dynamically serve infrastructure nodes, edges, and blast-radius visualizers.
*   **Machine Learning Engine:** Features an integrated anomaly detection pipeline (Unsupervised Machine Learning/Isolation Forest) that captures and scores network telemetry shifts in real-time.
*   **Modern Full-Stack Engineering:**
    *   **Frontend:** React 18 + TypeScript + Cytoscape.js (Deployed on Vercel)
    *   **Backend:** FastAPI + LiteLLM (Deployed on Render)
*   **Local Development Independence:** Designed to be completely buildable and testable on a local laptop environment, proving robust engineering versatility without mandatory cloud vendor lock-in during the development lifecycle.

---

## ⚙️ Local Development Setup

To run this architecture locally on your own machine:

### 1. Prerequisites
*   Python 3.11+
*   Node.js 18+

### 2. Backend Initialization
Navigate to the `/backend` directory and set up the Python environment:

```bash
cd backend
python -m venv venv
source venv/Scripts/activate  # On Windows
# On macOS/Linux: source venv/bin/activate
pip install --upgrade pip && pip install -r requirements.txt
```

Create a `.env` file in the backend directory with your cloud credentials:

```env
GROQ_API_KEY=gsk_your_api_key_here
LITELLM_DROP_PARAMS=True
NEO4J_URI="your_connection_string_here"
NEO4J_USER=neo4j
NEO4J_PASSWORD="your_password_here"

Launch the FastAPI server:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Frontend Initialization
Navigate to the `/frontend` directory:

```bash
cd frontend
npm install
```

Create a `.env` file in the frontend directory to point to your backend:

```env
VITE_API_URL=http://localhost:8000
```

Launch the Vite development server:

```bash
npm run dev
```

---

## 🏆 Hackathon Deployment

This project features an automated CI/CD pipeline. Pushes to the main branch automatically trigger zero-downtime production builds across Vercel (Edge UI) and Render (Python Web Services).
