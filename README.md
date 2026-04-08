# VAPT Dashboard - Unified Security Intelligence Platform

A comprehensive Vulnerability Assessment and Penetration Testing (VAPT) Dashboard that scans both web assets and IP infrastructure, providing a unified security view of your entire attack surface.

## 🚀 Features

### Core Asset System
- **Multi-type Asset Management**: Domains, Subdomains, IPs, CIDR Ranges, APIs, Servers, Cloud Resources
- **Rich Metadata**: Asset type, owner, risk score, scan history, discovered vulnerabilities
- **Automatic Discovery**: Network range scanning with host discovery

### Scanning Capabilities

#### Web Scanning
- OWASP Top 10 Detection
- SQL Injection
- Cross-Site Scripting (XSS)
- CSRF
- Authentication Flaws
- API Vulnerabilities

#### IP/Network Scanning
- Port Scanning
- Service Detection
- OS Fingerprinting
- Network Vulnerabilities
- Misconfigured Services

### Scanner Integrations
- **Nmap** - Port scanning and service detection
- **Masscan** - Large-scale network scanning
- **OpenVAS** - Network vulnerability scanning
- **Nuclei** - Template-based vulnerability scanning
- **Nikto** - Web server scanning
- **OWASP ZAP** - Web application scanning

### Advanced Features
- **Dynamic Risk Scoring**: Custom formula combining CVSS, asset criticality, exploit availability, and exposure
- **Attack Surface Visualization**: Interactive network maps with D3.js
- **Attack Path Analysis**: Predict potential attack chains
- **Vulnerability Heatmap**: Visual risk distribution
- **Security Posture Timeline**: Track trends over time
- **Continuous Monitoring**: Scheduled and on-demand scans
- **Multi-channel Alerting**: Email, Slack, Microsoft Teams
- **Geo-IP Mapping**: Location and ASN information
- **Red Team Mode**: Attacker simulation view

## 📁 Project Structure

```
VAPT_dash/
├── backend/                 # FastAPI Backend
│   ├── app/
│   │   ├── api/            # API routes
│   │   ├── core/           # Core configurations
│   │   ├── models/         # Database models
│   │   ├── schemas/        # Pydantic schemas
│   │   ├── services/       # Business logic
│   │   └── scanners/       # Scanner integrations
│   ├── requirements.txt
│   └── main.py
├── frontend/               # Next.js Frontend
│   ├── src/
│   │   ├── app/           # Next.js app router
│   │   ├── components/    # React components
│   │   ├── hooks/         # Custom hooks
│   │   ├── lib/           # Utilities
│   │   └── types/         # TypeScript types
│   ├── package.json
│   └── tailwind.config.js
├── docker/                 # Docker configurations
├── docker-compose.yml
└── README.md
```

## 🛠️ Technology Stack

### Frontend
- Next.js 14 (App Router)
- React 18
- TypeScript
- TailwindCSS
- Chart.js / Recharts
- D3.js (Network visualization)
- Zustand (State management)

### Backend
- FastAPI
- SQLAlchemy (ORM)
- Celery (Task queue)
- Redis (Caching & message broker)

### Database
- PostgreSQL (Primary database)
- Elasticsearch (Log aggregation & search)
- Redis (Caching)

### Scanner Layer
- Nmap / python-nmap
- Masscan
- Nuclei
- OpenVAS (via API)
- OWASP ZAP (via API)

## 🚀 Quick Start

### Using Docker (Recommended)

```bash
# Clone and navigate to project
cd VAPT_dash

# Start all services
docker-compose up -d

# Access the dashboard
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Manual Setup

#### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

## 📊 Dashboard Sections

1. **Overview** - Key metrics and security posture summary
2. **Attack Surface Map** - Interactive network visualization
3. **Vulnerability List** - Comprehensive vulnerability database
4. **Asset Inventory** - Complete asset management
5. **Scan History** - Historical scan data and trends
6. **Risk Analytics** - Advanced risk analysis and reporting
7. **Alerts** - Real-time security notifications
8. **Settings** - Configuration and integrations

## 🔒 Security Considerations

- All scanner operations run in isolated containers
- API authentication via JWT tokens
- Role-based access control (RBAC)
- Encrypted credentials storage
- Audit logging for all operations

## 📝 License

MIT License - See LICENSE file for details
