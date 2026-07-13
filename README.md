# 🛡️ Project Chronos: AI-Driven Cyber Resilience Digital Twin

Project Chronos is a real-time cyberattack simulation and automated incident response infrastructure monitoring dashboard. It bridges the gap between active threat modeling and automated SOAR (Security Orchestration, Automation, and Response) containment. By rendering an interactive, graph-based infrastructure digital twin, Chronos maps visual multi-stage attacks and executes autonomous, active containment strategies to isolate compromised environments before threats propagate.

---

## 🚀 Core Architecture Highlights

Our platform leverages a state-of-the-art decoupled architecture built for speed, resilience, and local independence:

*   **Multi-Agent GenAI Orchestrator:** Powered by **CrewAI** and **Groq**, utilizing the highly optimized **`llama-3.3-70b-versatile`** model. 
    *   *Red Agent (APT Simulator):* Autonomously discovers network topology and maps multi-stage lateral movements aligned with the MITRE ATT&CK framework.
    *   *Blue Agent (SOAR Orchestrator):* Performs active incident response, evaluates anomalies, cuts malicious paths, and writes standard compliance audit logs.
*   **Local Machine Independence:** Intentionally architected to run efficiently within a local development environment. By removing dependencies on heavy cloud vendor lock-ins, Chronos ensures complete deployment flexibility, low latency, and robust cross-platform versatility.
*   **Machine Learning Engine:** Features an integrated anomaly detection pipeline using an unsupervised **Isolation Forest** model to analyze shifting network telemetry metrics (hour of day, data payload sizes, login failures) and mathematically classify threats.
*   **Graph Database Topology:** Structured using a **Neo4j** relational architecture that dynamically serves infrastructure nodes, paths, and edges, allowing real-time mapping of network assets.
*   **Modern Stack:**
    *   *Frontend:* React 18 + TypeScript + Cytoscape.js (for digital twin canvas rendering).
    *   *Backend:* FastAPI + LiteLLM (for multi-provider model routing).

---

## ⚙️ Local Setup Instructions

### Prerequisites
*   **Python:** version 3.10+
*   **Node.js:** version 18+

### 1. Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd Chronos_Master/backend
   ```
2. Initialize and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create and configure your `.env` file inside `/backend` with the following variables:
   ```env
   GROQ_API_KEY=your_groq_api_key_here
   LITELLM_DROP_PARAMS=True
   NEO4J_URI=bolt://localhost:7687
   NEO4J_USER=neo4j
   NEO4J_PASSWORD=your_password
   ```
5. Launch the FastAPI server:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

### 2. Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd Chronos_Master/frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Configure the `.env` file inside `/frontend`:
   ```env
   VITE_API_BASE_URL=http://localhost:8000
   VITE_USE_MOCK_DATA=false
   VITE_POLLING_INTERVAL=1000
   ```
4. Launch the local development server:
   ```bash
   npm run dev
   ```
5. Open your browser and navigate to `http://localhost:5173` to access the digital twin topology dashboard.
