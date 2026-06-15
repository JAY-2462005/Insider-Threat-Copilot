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

## 🤖 Security Copilot: How It Works

The Security Copilot is an offline RAG (Retrieval-Augmented Generation) system that allows natural language queries against your security data.

### Architecture Flow

```
User Question (Natural Language)
    ↓
Intent Classification
    ↓
Pandas-Based Data Retrieval
    ↓
Evidence Aggregation
    ↓
Prompt Construction
    ↓
Local Qwen LLM (Ollama) → Structured Response
    ↓
Rich UI Rendering with Charts/Tables
```

### Intent Categories

The copilot classifies questions into specialized intents:

1. **Threat Investigation**: General security queries and incident analysis
2. **Employee Profile**: User-specific behavior analysis and risk assessment
3. **Alert Explanation**: Why specific alerts were triggered
4. **Flight Risk**: Pre-breach behavioral analysis and watchlist management
5. **Security Advisory**: Policy recommendations and best practices
6. **User Comparison**: Side-by-side risk comparison between users

### Data Retrieval Process

For each intent, the system uses Pandas operations to:

1. **Filter Data**: Apply relevant filters based on question context
2. **Aggregate Metrics**: Calculate risk scores, event counts, severity distributions
3. **Extract Evidence**: Gather relevant event details and user information
4. **Generate Recommendations**: Provide actionable SOC responses

### LLM Integration

- **Primary**: Local Qwen model via Ollama (offline, private)
- **Fallback**: Rule-based responses when Ollama is unavailable
- **Response Types**: Structured JSON with narrative, evidence tables, and recommendations

### Example Interactions

**User**: "Show me all critical incidents involving USB devices"
**System**: 
- Retrieves all events with destination_risk >= 4 (USB/external)
- Filters for CRITICAL severity
- Generates evidence table with user, department, timestamp details
- Provides SOC recommendations for USB threat mitigation

**User**: "Why was user.0058 flagged?"
**System**:
- Profiles user.0058's behavior patterns
- Compares against departmental baselines
- Shows specific risk factors that triggered the alert
- Provides detailed score breakdown and timeline

## 🔧 Installation & Setup

### Prerequisites

- Python 3.12+
- pip package manager
- (Optional) Ollama for local LLM
- (Optional) Qwen 2.5 model via Ollama
- (Optional) Google Gemini API key for enhanced summaries

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

## 🎯 Core Components Explained

### 1. Detection Engine (`backend/detector.py`)

**Hybrid Scoring Approach**:
- **ML Component (20%)**: IsolationForest for anomaly detection
- **Rule Component (80%)**: Explainable business rules
- **Seasonality Adjustment**: Reduces scores for expected patterns

**Risk Factors Scored**:
- High-risk destinations (USB, external email)
- Data sensitivity violations
- Volume anomalies (bulk export detection)
- Off-hours access patterns
- HR high-risk employee flags
- Unapproved asset access
- Junior staff policy violations

### 2. Flight Risk System (`backend/flight_risk.py`)

**Pre-Breach Indicators** (focusing on behavioral drift, not actual breach):
- HR risk flags
- Tenure analysis (< 6 months)
- Login time pattern shifts
- Access frequency changes
- Asset exploration patterns

**Risk Levels**: LOW, WATCHLIST, ELEVATED, HIGH FLIGHT RISK

### 3. Zero-Trust ChatOps (`frontend/pages/2_Alerts.py`)

**Triggering Logic**:
- Risk score: 70-89 (MEDIUM range)
- Destination risk ≤ 2 (internal network only)
- Avoids external/high-risk destinations

**User Flow**:
1. System sends automated message to user
2. User responds via verification buttons
3. "Yes" → Downgrade to false positive
4. "No" → Escalate to CRITICAL + account isolation

### 4. Security Copilot (`backend/copilot.py` + `frontend/pages/8_Security_Copilot.py`)

**RAG Pipeline**:
1. User asks natural language question
2. Intent classification routes to appropriate specialist
3. Pandas retrieves relevant evidence from security data
4. Context and evidence formatted into structured prompt
5. Local Qwen model generates analyst narrative
6. Rich UI renders response with tables, charts, recommendations

**Supported Query Types**:
- "Show me all critical incidents"
- "Why was user.0058 flagged?"
- "Who has high flight risk?"
- "Compare user.0058 and user.0092"
- "Which department generated most alerts?"
- "What needs to be done if a user is flagged?"

## 📊 Usage Examples

### Scenario 1: SOC Analyst Investigation

1. **Dashboard Monitoring**: Check executive dashboard for critical alerts
2. **Alert Triage**: Review alerts queue sorted by risk score
3. **Deep Investigation**: Use investigation workbench for baseline vs observed analysis
4. **Copilot Assistance**: Ask Security Copilot for context and recommendations
5. **Response**: Apply kill-switch for critical threats or verify via ChatOps

### Scenario 2: Executive Briefing

1. **AI Summary Page**: Review executive-level threat briefing
2. **Threat Patterns**: Understand common attack vectors
3. **Department Exposure**: Identify high-risk business units
4. **Priority Actions**: Review recommended response strategies
5. **Flight Risk**: Monitor pre-breach watchlist for proactive threats

### Scenario 3: Threat Hunting

1. **Security Copilot**: Ask natural language questions to hunt for threats
2. **Analytics Page**: Use visualizations to identify patterns
3. **User Profiling**: Investigate specific user behavior over time
4. **Comparative Analysis**: Compare users to identify outliers
5. **Simulation**: Test scenarios using threat simulation lab

## 🎨 UI Features

### Dashboard
- Real-time metrics with severity breakdown
- Highest priority incident highlighting
- Platform capability overview
- Process flow visualization
- Recent scored events table

### Alerts Queue
- Severity-based filtering
- Department and username filters
- Expandable detailed alert cards
- ChatOps integration for medium-risk alerts
- Kill-switch buttons for critical threats
- Deep dive investigation links

### Investigation Workbench
- Baseline vs observed behavior comparison
- Flight risk assessment integration
- Mathematical risk breakdown
- AI-powered verdict generation
- SOC playbook recommendations
- Timeline reconstruction

### AI Summary
- Enterprise threat level gauge
- Visual threat pattern distribution
- Severity breakdown pie charts
- Risk score histograms
- Department exposure analysis
- Priority response timeline
- Key insights and recommendations

### Security Copilot
- Natural language query interface
- Quick action buttons for common queries
- Rich response rendering with tables/charts
- Intent classification for accurate responses
- Offline RAG with local LLM
- Evidence-based recommendations

## 🔒 Security Features

### Data Privacy
- **Local Processing**: All ML detection happens locally
- **Offline LLM**: Security Copilot uses local Qwen model
- **No Cloud Dependencies**: Core functionality works without internet
- **Configurable API Keys**: Optional Gemini integration for enhanced features

### Access Control
- **Kill-Switch Simulation**: Account isolation for critical threats
- **ChatOps Verification**: User confirmation for medium-risk alerts
- **Role-Based Views**: Different views for executives vs analysts
- **Audit Trail**: All actions logged in session state

## 📈 Performance Metrics

### Detection Accuracy
- **Precision**: High precision for critical threats
- **Recall**: Comprehensive coverage of insider threat patterns
- **F1-Score**: Balanced performance across severity levels
- **False Positive Rate**: ChatOps helps reduce false positives

### System Performance
- **Processing Speed**: Sub-second scoring for individual events
- **Batch Processing**: Efficient handling of large datasets
- **Memory Usage**: Optimized for standard development machines
- **UI Responsiveness**: Real-time updates with minimal latency

## 🛠️ Configuration

### Risk Threshold Adjustment
```python
# In sidebar slider
Risk Score Threshold: 0-100 (default: 70)
```

### Severity Classification
```python
CRITICAL: risk_score >= 90
HIGH: 75 <= risk_score < 90
MEDIUM: 50 <= risk_score < 75
LOW: risk_score < 50
```

### ChatOps Triggering
```python
trigger_chatops = (70 <= risk_score <= 89) and (destination_risk <= 2)
```

## 🧪 Testing

### Run Backend Tests
```bash
python test_backend.py
```

### Run ChatOps Tests
```bash
python test_chatops.py
```

### Generate Test Data
```bash
cd backend
python generate_ps4_data.py
```

## 🚀 Deployment

### Local Development
```bash
cd frontend
streamlit run app.py
```

### Production Deployment
1. Set up reverse proxy (nginx)
2. Configure SSL certificates
3. Set up process monitoring (systemd)
4. Configure log rotation
5. Set up backup procedures

### Docker Deployment (Future)
```dockerfile
# Dockerfile example
FROM python:3.12
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["streamlit", "run", "frontend/app.py"]
```

## 📚 Documentation Files


- **README.md**: This comprehensive system documentation

## 🤝 Contributing

This is a demonstration project for insider threat detection. Key areas for enhancement:

1. **Persistent Storage**: Database integration for alert history
2. **Real-time Streaming**: Live data ingestion from SIEM
3. **Advanced ML**: Deep learning models for behavior analysis
4. **Integration**: Real AD/SOAR integration for kill-switch
5. **Multi-tenant**: Support for multiple organizations

## 📄 License

This project is provided as-is for educational and demonstration purposes.

## 🙏 Acknowledgments

- **Streamlit**: For the amazing frontend framework
- **Scikit-learn**: For ML algorithm implementation
- **Ollama**: For local LLM capabilities
- **Google Gemini**: For enhanced AI summaries
- **Plotly**: For interactive visualizations

---

**Built with ❤️ for security teams who need explainable AI and fast response capabilities.**
