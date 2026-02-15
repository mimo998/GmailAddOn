# Email Security Scorer - Gmail Add-on

A Gmail Add-on that analyzes opened emails and produces a maliciousness score (0-100, 0-Safe 100-Malicious).

## Overview

The add-on provides real-time email threat analysis using three different detection approaches:

1. **Deterministic Pattern Matching** - Rule-based detection for known threat indicators.
2. **AI/LLM Analysis** - Intelligent analysis using large language models.
3. **VirusTotal Integration** - URL reputation checking against 70+ security vendors.


## File Structure

| File | Purpose |
|------|---------|
| `appsscript.json` | Add-on manifest with permissions and triggers |
| `Main.gs` | Entry points, email data extraction |
| `Analysis.gs` | Deterministic scoring engine |
| `LLMAnalysis.gs` | AI-powered analysis via OpenRouter |
| `VirusTotal.gs` | URL reputation checking |
| `UI.gs` | Card-based user interface |
| `Storage.gs` | Whitelist, blacklist, and history management |

## APIs Used

### 1. Gmail API (Google Workspace)
- **Purpose**: Read email content, headers, attachments
- **Scopes**: `gmail.addons.execute`, `gmail.addons.current.message.readonly`

### 2. OpenRouter API (AI/LLM)
- **Purpose**: Intelligent email content analysis
- **Models**: Auto-fallback through multiple free models:
  - `meta-llama/llama-4-maverick:free`
  - `deepseek/deepseek-chat-v3-0324:free`
  - `mistralai/mistral-small-3.1-24b-instruct:free`
- **Rate Limit**: Varies by model

### 3. VirusTotal API v3
- **Purpose**: URL reputation checking against 70+ security vendors
- **Rate Limit**: 4 requests/minute, 500 requests/day (free tier)
- **Features**: URL lookup, scan submission, threat scoring

## Setup Instructions

### 1. Create Apps Script Project

1. Go to [script.google.com](https://script.google.com)
2. Click **New Project**
3. Name it "Email Security Scorer"

### 2. Add Code Files

1. **Project Settings** (gear icon) → Check "Show appsscript.json manifest file"
2. Replace `appsscript.json` content with provided manifest
3. Create script files for each `.gs` file and paste the code

### 3. Configure API Keys (Required for full functionality)

Go to **Project Settings** → **Script Properties** and add:

| Property Name | Value | Required |
|---------------|-------|----------|
| `OPENROUTER_API_KEY` | Your OpenRouter API key (`sk-or-...`) | Optional (enables AI) |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API key | Optional (enables VT) |

**Getting API Keys:**
- **OpenRouter**: Sign up at [openrouter.ai](https://openrouter.ai) → Keys → Create new key (free tier available)
- **VirusTotal**: Sign up at [virustotal.com](https://virustotal.com) → Profile → API key (free tier available)

>  **Important**: The add-on works without API keys but with reduced functionality. Deterministic pattern matching will still work, but AI analysis and VirusTotal checks will be disabled.

### 4. Deploy Add-on

1. **Deploy** → **Test deployments** → **Install**
2. Open Gmail and click any email
3. Find the shield icon in the right sidebar

## Implemented Features

### Core Analysis Engine

#### 1. Deterministic Pattern Matching
Rule-based detection that always runs:
- **Header Analysis**: Checks SPF, DKIM, DMARC authentication status
- **Content Analysis**: Detects urgency language, scam phrases, sensitive data requests
- **URL Analysis**: Identifies IP-based URLs, URL shorteners, suspicious domain patterns
- **Attachment Analysis**: Flags dangerous file types (.exe, .scr, .bat) and macro-enabled documents

#### 2. AI/LLM Analysis
LLM is known best for understanding natural language, therefore it is used and partially affects the score like so:

- Detects social engineering tactics
- Identifies context mismatches (e.g., university email offering gaming currency)
- Provides human-readable explanations
- Uses balanced prompting to avoid over-flagging legitimate emails
- **Auto-fallback**: Tries multiple free models if one is rate-limited

#### 3. VirusTotal Integration
Real-time URL reputation checking:

- Queries 70+ security vendors for each URL
- **Clean URLs reduce score by 25 points** (rewards verified safe links)
- Malicious URLs add 25-40 points depending on severity
- Rate-limit aware: only checks first 2 URLs per email

### Scoring System

| Score Range | Verdict | Description |
|-------------|---------|-------------|
| 0-9 | ✅ SAFE | No significant threats detected |
| 10-29 | ℹ️ CAUTION | Minor concerns, likely safe |
| 30-59 | ⚠️ SUSPICIOUS | Review carefully before acting |
| 60-100 | ⛔ MALICIOUS | Strong indicators of threat |

### User Management Features

#### Whitelist (Trusted Senders)
- **Reduces score by 50%** for whitelisted senders
- Built-in trusted domains: Google, Amazon, Netflix, Spotify, GitHub, HoYoverse, Steam, PayPal, Israeli banks, etc.
- Users can add custom trusted emails and domains via UI
- **Safety override**: If scam content is detected, whitelist protection is automatically bypassed to prevent compromised account attacks

#### Blacklist (Blocked Senders)
- Blacklisted emails: +50 points
- Blacklisted domains: +40 points
- User-managed via UI

#### Scan History
- Tracks last 50 email scans
- Shows date, sender, subject, score, and verdict
- Clearable by user


## 📊 Scoring Logic

### Signal Categories & Weights

| Category | Signal | Points |
|----------|--------|--------|
| **Blacklist** | Exact email match | +50 |
| | Domain match | +40 |
| **Headers** | SPF fail | +25 |
| | DKIM fail | +25 |
| | DMARC fail | +20 |
| **Content** | High urgency language | +20 |
| | Scam/prize patterns | +20 |
| | Sensitive data request | +25 |
| | Suspicious subject | +25 |
| **URLs** | IP-based URLs | +25 |
| | Shortened URLs | +15 |
| | Insecure HTTP | +15 |
| | Suspicious domain keywords | +25 |
| **Attachments** | Dangerous file types | +35 |
| | Macro-enabled docs | +25 |
| **VirusTotal** | Malicious (5+ vendors) | +40 |
| | Suspicious | +10 |
| | **Clean** | **-25** |
| **AI Analysis** | Based on LLM assessment | +0 to +40 |
| **Whitelist** | Trusted sender (no scam content) | **×0.5** |

