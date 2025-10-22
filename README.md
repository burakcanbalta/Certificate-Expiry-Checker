# 📜 Certificate Expiry Checker

A comprehensive SSL/TLS certificate monitoring and alerting system designed for security teams and DevOps. Automatically track certificate expiration dates, monitor compliance, and receive proactive alerts before certificates expire.

---

## 🎯 Purpose

Monitor SSL/TLS certificates for multiple domains, ensure compliance with organizational policies, receive alerts for certificates nearing expiration, and generate reports for auditors or security teams.

---

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Python 3.8+
python --version

# Install required packages
pip install aiohttp python-dateutil
```

### 2. Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/CertificateExpiryChecker.git
cd CertificateExpiryChecker

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add domains to monitor
echo "google.com" >> domains.txt
echo "github.com" >> domains.txt
echo "yourdomain.com" >> domains.txt

# 4. Run certificate check
python certificate_checker.py --check

# 5. Start continuous monitoring service
python certificate_checker.py --monitor --interval 3600
```

---

## ⚡ Basic Usage

```bash
# Check a single domain
python certificate_checker.py --domain google.com

# Check multiple domains from a file
python certificate_checker.py --file domains.txt

# Generate compliance report
python certificate_checker.py --report --format json

# Continuous monitoring every hour
python certificate_checker.py --monitor --interval 3600

# Check with custom thresholds
python certificate_checker.py --check --warning-days 30 --critical-days 7
```

---

## 🛡️ Features

* **Multi-Domain Certificate Checking**

  * Bulk domain processing for hundreds of domains
  * Multiple port support: 443, 8443, 9443, and custom ports
  * Parallel scanning for high performance
  * Full certificate info: issuer, subject, algorithms, key strength

* **Advanced Alerting System**

  * Multi-channel alerts: Email, Slack, Discord
  * Configurable thresholds: warning, critical, expired
  * Smart alerting: only alert when approaching expiry
  * Alert history tracking in database

* **Compliance & Reporting**

  * PCI-DSS and ISO27001 ready reports
  * Multiple formats: JSON, CSV, Text
  * Historical tracking and auto-reporting

* **Enterprise Monitoring**

  * Continuous 24/7 monitoring
  * Performance metrics: duration, success rates
  * Robust error handling and retries
  * Comprehensive audit logging

---

## 🧪 Use Cases

**SOC Monitoring**

```bash
# Continuous monitoring for security teams
python certificate_checker.py --monitor --interval 3600
```

**Example alert:**

```
🚨 CRITICAL: api.yourservice.com expires in 5 days
```

**DevOps Pipeline**

```bash
# Pre-deployment certificate check
python certificate_checker.py --file production_domains.txt --critical-days 90

# Fail pipeline if critical certificates found
```

**Compliance Auditing**

```bash
# Generate compliance report for auditors
python certificate_checker.py --report --format json --report-type compliance
```

**Incident Response**

```bash
# Emergency certificate status check
python certificate_checker.py --domain compromised-service.com
```

---

## 📊 Sample Output

**Certificate Check**

```bash
Domain: google.com
Status: VALID
Days until expiry: 45
Expiry date: 2024-06-15 12:00:00
Issuer: CN=Google Trust Services LLC
```

**Compliance Report**

```text
Certificate Compliance Report
==================================================
Total Certificates: 156
Expired: 2
Critical: 5
Warning: 12
Valid: 137
Average Days Remaining: 89.5
Minimum Days Remaining: 3

Critical Certificates:
  api.service.com: 3 days (CRITICAL)
  auth.company.com: -2 days (EXPIRED)
```

---

## 🔧 Advanced Usage

**Custom Configuration**

```json
{
  "alert_thresholds": {
    "warning": 45,
    "critical": 14,
    "expired": 0
  }
}
```

**Docker Deployment**

```bash
# Build and run Docker container
docker build -t certificate-checker .
docker run -d \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/data:/app/data \
  certificate-checker
```

**CI/CD Integration (GitHub Actions example)**

```yaml
- name: Check Certificates
  run: |
    python certificate_checker.py --file domains.txt
    if [ $? -ne 0 ]; then
      echo "Critical certificates found!"
      exit 1
    fi
```

---

## 🐛 Troubleshooting

* **Certificate validation errors**: Increase timeout for slow servers

```bash
python certificate_checker.py --check --timeout 30
```

* **SMTP issues**: Configure SMTP credentials properly using app passwords

```json
{
  "smtp": {
    "server": "smtp.gmail.com",
    "port": 587,
    "username": "your-email@gmail.com",
    "password": "app-password"
  }
}
```

* **Performance optimization**: Adjust max concurrent workers

```bash
python certificate_checker.py --check --max-workers 5
```

---

## 🤝 Contributing

* Fork the repository
* Create a feature branch
* Commit changes
* Push branch and submit pull request

**Areas for contribution:**

* Additional certificate checks (OCSP, CRL)
* More alert channels (Teams, PagerDuty)
* Cloud provider integration (AWS ACM, Azure Key Vault)
* Enhanced reporting and visualization

---
