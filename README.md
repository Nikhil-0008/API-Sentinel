# API Sentinel

### Intelligent Real-Time API Security Gateway

> **Detect. Decide. Defend.**

API Sentinel is a real-time API security gateway designed to help developers and security teams detect, prevent, analyze, and respond to API security threats.

Modern applications rely heavily on APIs, which makes them a major attack surface for threats such as broken authentication, injection attacks, excessive data exposure, unauthorized access, and API abuse.

API Sentinel sits between API clients and backend services. It inspects API traffic, identifies suspicious behavior, calculates risk, applies security controls, protects API responses, and provides a dashboard where security teams can investigate and manage threats.

---

## INIT'26 Challenge Alignment

API Sentinel is designed around the three main requirements of the INIT'26 API Security challenge.

### 1. Detection Strategy

The system analyzes API traffic in real time to identify vulnerable and suspicious behavior.

It currently supports detection of:

* SQL Injection
* Cross-Site Scripting (XSS)
* Command Injection
* Broken or Missing Authentication
* BOLA / Unauthorized Object Access
* Rate Abuse and Suspicious Request Patterns
* Unknown or Undocumented API Endpoints
* Suspicious API Behavior
* Excessive or Unexpected Response Data

Each request goes through a security inspection and risk-scoring process before it reaches the backend.

---

### 2. Control and Safeguard System

Detecting a threat is only the first step. API Sentinel can automatically respond to the detected risk.

Based on the calculated risk, the gateway can:

* Allow legitimate requests
* Throttle suspicious traffic
* Block malicious requests
* Enforce authentication-related policies
* Redact sensitive response fields
* Create security incidents
* Record security events
* Trigger AI-assisted analysis

The basic request flow is:

```text
Incoming Request
       |
       v
Security Inspection
       |
       v
Threat Detection
       |
       v
Risk Score
       |
       +----------+----------+
       |          |          |
       v          v          v
     ALLOW     THROTTLE     BLOCK
       |
       v
Backend API
```

---

### 3. Decision Dashboard

Security teams need more than a simple blocked request message. They need to understand what happened, why the request was flagged, what action was taken, and what should be done next.

API Sentinel provides a centralized security dashboard with:

* Total API requests
* Blocked requests
* Suspicious requests
* Active incidents
* Attack attempts
* Shadow and undocumented APIs
* Attack distribution
* Security event timeline
* API Security Score
* Event-level security analysis
* AI-generated explanations
* AI Security Analyst
* Security-team override controls

---

# Architecture

```text
                         API Client
                             |
                             v
                  +----------------------+
                  |     API SENTINEL     |
                  |   Security Gateway   |
                  +----------+-----------+
                             |
             +---------------+---------------+
             |               |               |
             v               v               v
       Threat Detection   Risk Engine    AI Security
                                          Analyst
             |               |               |
             +---------------+---------------+
                             |
                             v
                  +----------------------+
                  |  Security Decision   |
                  |                      |
                  |  ALLOW               |
                  |  THROTTLE            |
                  |  BLOCK               |
                  +----------+-----------+
                             |
                             v
                       Backend API
                             |
                             v
                    Response Inspection
                             |
                    +--------+--------+
                    |                 |
                    v                 v
               Safe Response    Sensitive Data
                                 Redaction


                  +----------------------+
                  |  Security Dashboard |
                  |                      |
                  | Events               |
                  | Incidents            |
                  | Shadow APIs          |
                  | Attack Types         |
                  | Timeline             |
                  | Security Score       |
                  | AI Analysis          |
                  | Overrides             |
                  +----------------------+
```

---

# Detection Engine

API Sentinel inspects API requests before forwarding them to the backend.

## SQL Injection

Detects suspicious SQL-related patterns in request parameters and payloads.

```text
GET /api/users?id=1' OR '1'='1'

SQL Injection Detected
Risk: High
Action: BLOCK
```

## Cross-Site Scripting

Identifies potentially malicious script payloads.

```text
POST /api/profile

<script>alert(1)</script>

XSS Detected
Action: BLOCK
```

## Command Injection

Detects suspicious operating-system command patterns.

```text
GET /api/system?cmd=whoami

Command Injection Detected
Action: BLOCK
```

## Broken Authentication

Identifies requests attempting to access protected resources without the expected authentication information.

```text
GET /api/admin/users
Authorization: —

Authentication Violation
Action: BLOCK
```

## BOLA / Unauthorized Object Access

API Sentinel can identify suspicious object-level access patterns and flag potential unauthorized access to API resources.

## Rate Abuse

Repeated or abnormal requests can increase the security risk associated with a client and trigger throttling or blocking.

## Unknown and Shadow APIs

Previously unseen or undocumented endpoints are tracked so security teams can identify potentially exposed API surfaces.

---

# Risk-Based Security Decisions

API Sentinel does not treat every suspicious request in the same way.

The gateway evaluates the request, assigns a risk score, and applies an appropriate action.

```text
                    Request
                       |
                       v
                 Security Rules
                       |
                       v
                   Risk Score
                       |
          +------------+------------+
          |            |            |
          v            v            v
         LOW        MEDIUM        HIGH
          |            |            |
          v            v            v
        ALLOW       THROTTLE      BLOCK
```

This allows the system to distinguish between normal traffic, suspicious behavior, and high-risk attacks.

---

# Response Protection

API security does not stop after a request reaches the backend.

A backend API can accidentally expose sensitive or internal information through its responses.

API Sentinel inspects backend responses and can redact sensitive or unexpected fields before returning the response to the client.

The process is:

```text
Backend Response
       |
       v
Response Inspection
       |
       v
Sensitive / Unexpected Fields
       |
       v
Redaction
       |
       v
Sanitized API Response
```

Example:

```json
{
  "name": "User",
  "email": "user@example.com",
  "password_hash": "[REDACTED]",
  "api_secret": "[REDACTED]"
}
```

This provides protection against excessive data exposure at the API gateway layer.

---

# AI Security Analyst

API Sentinel integrates OpenRouter as an AI analysis layer.

The AI does not replace the real-time security detection and enforcement system. The security rules and risk engine provide the immediate decision, while the AI provides deeper analysis and explanation.

For detected security events, the AI can analyze:

* Attack type
* Severity
* Confidence
* Attack intent
* Explanation
* Recommended action
* Mitigation
* Incident summary

Example:

```text
Security Event

Attack Type: SQL Injection
Severity: Critical
Confidence: 98%
Risk Score: 94

Explanation:
Suspicious SQL injection patterns were detected
in the request parameters.

Recommended Action:
Block the request and investigate the affected endpoint.

Mitigation:
Use parameterized queries and strict input validation.
```

---

# AI Security Chat

Security teams can interact with the API Sentinel security assistant.

The assistant receives recent security events and incidents as context and can help answer questions such as:

```text
What are the most common attacks?

Why was this request blocked?

Which endpoints look suspicious?

What should I do about this incident?

Are there any undocumented APIs?
```

This provides an interactive way to investigate security events instead of manually going through individual logs.

---

# Security Dashboard

The dashboard provides a centralized view of the API security posture.

Example metrics include:

```text
+------------------------------------------------+
|              API SECURITY SCORE                |
|                    91 / 100                    |
+----------------+----------------+--------------+
| Total Requests |    Blocked     |  Suspicious  |
|     1,284      |      137       |      82      |
+----------------+----------------+--------------+
|   Incidents    |   Shadow APIs  | Attack Attempts|
|       9        |       4        |      137     |
+----------------+----------------+--------------+
```

Security engineers can investigate:

* Security events
* Active incidents
* Blocked requests
* Attack categories
* Exposed APIs
* Security timeline
* AI analysis
* Overall security score

---

# Attack Replay and Testing

API Sentinel includes an attack simulation system for testing the gateway.

The current demonstration scenarios include:

```text
SQL Injection
XSS
BOLA
Rate Abuse
Command Injection
Unknown Endpoint
Missing Authentication
```

This allows the complete security workflow to be demonstrated in a controlled environment.

```text
Attack Simulation
       |
       v
API Sentinel Detection
       |
       v
Risk Calculation
       |
       v
Automatic Action
       |
       v
Incident Creation
       |
       v
AI Analysis
       |
       v
Dashboard Visualization
```

---

# Security Event Storage

API Sentinel uses SQLite for local security-event and incident storage.

The system stores information required for:

* Event history
* Incident tracking
* Attack analysis
* Dashboard statistics
* Security scoring
* AI context
* Security investigations

---

# API Endpoints

## Security Dashboard

```http
GET /
```

## Security Statistics

```http
GET /api/security/stats
```

## Security Events

```http
GET /api/security/events
```

## Security Incidents

```http
GET /api/security/incidents
```

## Security Scores

```http
GET /api/security/scores
```

## Shadow APIs

```http
GET /api/security/shadow-apis
```

## Attack Distribution

```http
GET /api/security/attack-distribution
```

## Security Timeline

```http
GET /api/security/timeline
```

## AI Analysis

```http
GET /api/security/ai-analysis/<event_id>
```

## AI Security Chat

```http
POST /api/security/chat
```

## Security Override

```http
POST /api/security/unblock/<event_id>
```

---

# Technology Stack

| Technology              | Purpose                              |
| ----------------------- | ------------------------------------ |
| Python                  | Core application                     |
| Flask                   | API gateway and backend              |
| SQLite                  | Security events and incident storage |
| OpenRouter              | AI security analysis and assistant   |
| Requests                | API communication and proxying       |
| HTML / CSS / JavaScript | Security dashboard                   |
| REST APIs               | Gateway and security endpoints       |

---

# Getting Started

## 1. Clone the Repository

```bash
git clone (https://github.com/Nikhil-0008/API-Sentinel.git)
cd api-sentinel
```

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 4. Configure Environment Variables

Create a `.env` file:

```env
BACKEND_URL=http://localhost:6000
OPENROUTER_API_KEY=your_openrouter_api_key
OPENROUTER_MODEL=your_preferred_model
```

For deployment with a real backend:

```env
BACKEND_URL=https://your-real-api.internal
```

Do not commit API keys or other secrets to the repository.

## 5. Run API Sentinel

```bash
python app.py
```

The gateway runs on:

```text
http://127.0.0.1:5000
```

Open the dashboard from the root endpoint.

---

# Testing the Gateway

A normal API request can be sent through the gateway:

```bash
curl -X GET \
  "http://127.0.0.1:5000/api/users/1" \
  -H "accept: application/json"
```

Malicious requests can be tested using the built-in attack replay functionality.

Example workflow:

```text
SQL Injection
      |
      v
Detection
      |
      v
Risk Score
      |
      v
BLOCK
      |
      v
Incident
      |
      v
AI Explanation
      |
      v
Dashboard
```

---

# Why API Sentinel?

Traditional API monitoring often focuses on logging what happened after an incident.

API Sentinel focuses on the complete security lifecycle:

### Detect

Identify malicious and suspicious API behavior in real time.

### Decide

Evaluate risk and determine the appropriate security action.

### Defend

Automatically allow, throttle, block, or sanitize API traffic.

### Explain

Use AI-assisted analysis to explain security events and recommend mitigation.

### Visualize

Give security teams a centralized view of API exposure, threats, incidents, and overall security posture.

---

# Key Features

* Real-time API traffic inspection
* Automated threat detection
* Risk-based security decisions
* Automatic request blocking
* Rate-abuse detection and throttling
* Authentication protection
* SQL injection detection
* XSS detection
* Command injection detection
* BOLA detection
* Shadow API discovery
* Response data protection
* AI-powered security analysis
* AI security assistant
* Interactive security dashboard
* Incident correlation
* Attack replay and testing
* Security-team override capability
* API security scoring

---

# Future Scope

The system can be extended with:

* Machine-learning-based behavioral anomaly detection
* OpenAPI specification analysis
* Automatic API schema discovery
* JWT and OAuth security analysis
* Distributed rate limiting
* Redis-based event storage
* Cloud deployment
* Kubernetes and API gateway integration
* Automated vulnerability discovery
* Continuous API security posture monitoring
* Advanced API abuse detection
* Automated incident response workflows
* Threat-intelligence integration

---

# Disclaimer

API Sentinel is a security research and hackathon prototype intended for authorized testing, development, and defensive security use.

Only test APIs and systems that you own or have explicit permission to assess.

---

# Developed By

## Nikhil Penumala & Bala Kiran Janaki

> Built with purpose. Built to detect. Built to protect.

---

<p align="center">

### API Sentinel

**Monitor. Detect. Analyze. Protect.**

Built for the **INIT'26 API Security Challenge**

</p>
