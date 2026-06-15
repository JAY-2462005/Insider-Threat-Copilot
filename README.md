# Insider Threat Copilot 🛡️

A comprehensive AI-powered insider threat detection platform that combines statistical baselining, machine learning, and GenAI to catch data exfiltration, generate human-readable threat narratives, and feature a simulated Zero-Trust ChatOps response system.

## 🚀 Key Features

- **Hybrid Detection Engine**: ML-based anomaly detection combined with explainable rule-based scoring
- **Real-time Risk Scoring**: 0-100 risk scores with detailed breakdowns for every alert
- **AI-Powered Narratives**: Gemini-backed SOC summaries with intelligent fallbacks
- **Security Copilot**: Offline RAG chatbot using local Qwen model for natural language queries
- **Flight Risk Prediction**: Pre-breach behavioral analysis to identify potential insider threats before exfiltration
- **Zero-Trust ChatOps**: Automated user verification for medium-risk alerts to filter false positives
- **Kill-Switch Integration**: Simulated account isolation for critical threats
- **Interactive Dashboard**: Executive-ready visualizations and threat analytics

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DATA INGESTION LAYER                      │
│  CSV Logs (data_access_logs.csv) + User Profiles            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  BACKEND DETECTION ENGINE                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Feature Engineering                                 │  │
│  │  • Off-hours access detection                        │  │
│  │  • Volume anomaly analysis                           │  │
│  │  • Data sensitivity scoring                          │  │
│  │  • Destination risk assessment                       │  │
│  │  • Behavioral drift detection                        │  │
│  └──────────────────────────────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Hybrid Scoring Engine                               │  │
│  │  • IsolationForest ML (20% weight)                   │  │
│  │  • Rule-based scoring (80% weight)                   │  │
│  │  • Seasonality adjustment                            │  │
│  │  • Flight risk calculation                           │  │
│  └──────────────────────────────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Alert Generation & ChatOps Logic                    │  │
│  │  • Severity classification                           │  │
│  │  • Zero-Trust ChatOps triggering                     │  │
│  │  • SOC action recommendations                        │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   FRONTEND UI LAYER                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │   Dashboard     │  │   Alerts Queue  │  │Investigation ││
│  │   Executive view│  │   SOC triage    │  │Deep dive     ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │   AI Summary    │  │  Flight Risk    │  │   Security   ││
│  │   Briefing      │  │  Pre-breach     │  │   Copilot    ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    AI/LLM INTEGRATION                        │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │   Gemini API    │  │   Ollama Qwen   │                   │
│  │  (Executive     │  │   (Security     │                   │
│  │   Summaries)    │  │   Copilot RAG)  │                   │
│  └─────────────────┘  └─────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```
## 🔧 Installation & Setup

### Prerequisites

- Python 3.12+
- pip package manager
- Ollama for local LLM
- Qwen 2.5 model via Ollama
- Google Gemini API key for enhanced summaries

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Insider-Threat-Copilot
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   # Create .env file
   touch .env
   
   # Add optional API keys
   GEMINI_API_KEY=your_gemini_api_key_here
   GEMINI_MODEL=gemini-3.5-flash
   OLLAMA_MODEL=qwen2.5:1.5b
   OLLAMA_HOST=http://127.0.0.1:11434
   ```

5. **Generate sample data**
   ```bash
   cd backend
   python generate_ps4_data.py
   ```

6. **Run the detection system**
   ```bash
   cd backend
   python detector.py
   ```

7. **Launch the frontend**
   ```bash
   cd frontend
   streamlit run app.py
   ```

### Ollama Setup (for Security Copilot)

1. **Install Ollama**
   ```bash
   curl -fsSL https://ollama.ai/install.sh | sh
   ```

2. **Pull Qwen model**
   ```bash
   ollama pull qwen2.5:1.5b
   ```

3. **Verify installation**
   ```bash
   ollama list
   ```

## 📁 Project Structure

```
Insider-Threat-Copilot/
├── backend/
│   ├── detector.py              # Main detection engine with hybrid ML + rules
│   ├── copilot.py               # Security Copilot RAG implementation
│   ├── data_detective.py        # Intent classification and data retrieval
│   ├── flight_risk.py           # Pre-breach behavioral analysis
│   ├── llm_summary.py           # Gemini-backed executive summaries
│   ├── generate_ps4_data.py     # Sample data generation
│   ├── evaluate.py              # Model evaluation metrics
│   └── utils.py                 # Utility functions
├── frontend/
│   ├── app.py                   # Main Streamlit application
│   ├── data_service.py          # Data loading and caching
│   ├── components/
│   │   ├── theme.py             # UI theming and chart helpers
│   │   ├── kill_switch.py       # Account isolation simulation
│   │   ├── copilot.py           # Copilot navigation buttons
│   │   └── charts.py            # Custom chart components
│   └── pages/
│       ├── 1_Dashboard.py       # Executive dashboard
│       ├── 2_Alerts.py          # Alert queue with ChatOps
│       ├── 3_Investigation.py   # Detailed investigation workbench
│       ├── 4_Analytics.py       # Security analytics and visualizations
│       ├── 5_AI_Summary.py      # AI-powered executive briefings
│       ├── 6_Threat_Simulation_(ATO).py  # Account takeover simulation
│       ├── 7_Flight_Risk.py     # Flight risk radar and watchlist
│       └── 8_Security_Copilot.py # AI chatbot interface
├── data/
│   ├── data_access_logs.csv     # Access event logs
│   └── user_profiles.csv        # User baseline profiles
├── outputs/
│   └── alerts.json              # Generated alerts with scores
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

**Built with ❤️ for security teams who need explainable AI and fast response capabilities.**
