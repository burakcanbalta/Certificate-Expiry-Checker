import ssl
import socket
import OpenSSL
from datetime import datetime, timedelta
import asyncio
import aiohttp
import sqlite3
import json
import argparse
import smtplib
import requests
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from logging.handlers import RotatingFileHandler
import sys
import os
from pathlib import Path

class CertificateChecker:
    def __init__(self, db_path="certificates.db", config_file="config.json"):
        self.db_path = db_path
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.init_database()

    def load_config(self, config_file):
        default_config = {
            "alerting": {
                "smtp": {
                    "server": "smtp.gmail.com",
                    "port": 587,
                    "username": "",
                    "password": "",
                    "from_email": "",
                    "to_email": ""
                },
                "slack_webhook": "",
                "discord_webhook": "",
                "alert_thresholds": {
                    "warning": 30,
                    "critical": 7,
                    "expired": 0
                }
            },
            "monitoring": {
                "default_ports": [443, 8443, 9443],
                "timeout": 10,
                "max_workers": 10
            },
            "reporting": {
                "auto_generate": True,
                "report_path": "./reports"
            }
        }

        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    return self.merge_configs(default_config, user_config)
            except Exception as e:
                print(f"Config load error: {e}")
        
        return default_config

    def merge_configs(self, default, user):
        result = default.copy()
        for key, value in user.items():
            if isinstance(value, dict) and key in result:
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler('certificate_checker.log', maxBytes=10485760, backupCount=5),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                port INTEGER,
                issuer TEXT,
                subject TEXT,
                not_before DATETIME,
                not_after DATETIME,
                days_until_expiry INTEGER,
                status TEXT,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
                signature_algorithm TEXT,
                public_key_algorithm TEXT,
                public_key_bits INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                port INTEGER,
                check_result TEXT,
                error_message TEXT,
                check_duration REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                alert_type TEXT,
                message TEXT,
                severity TEXT,
                sent BOOLEAN DEFAULT FALSE,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT,
                report_data TEXT,
                generated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def get_certificate_info(self, domain, port=443):
        start_time = time.time()
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=self.config['monitoring']['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    cert_info = self.parse_certificate(cert, domain, port)
                    check_duration = time.time() - start_time
                    
                    self.save_certificate_check(domain, port, "SUCCESS", "", check_duration)
                    return cert_info
                    
        except Exception as e:
            check_duration = time.time() - start_time
            self.save_certificate_check(domain, port, "FAILED", str(e), check_duration)
            self.logger.error(f"Certificate check failed for {domain}:{port} - {e}")
            return None

    def parse_certificate(self, cert, domain, port):
        issuer = cert.get_issuer()
        subject = cert.get_subject()
        
        not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        
        days_until_expiry = (not_after - datetime.now()).days
        status = self.get_certificate_status(days_until_expiry)
        
        return {
            'domain': domain,
            'port': port,
            'issuer': self.format_x509_name(issuer),
            'subject': self.format_x509_name(subject),
            'not_before': not_before,
            'not_after': not_after,
            'days_until_expiry': days_until_expiry,
            'status': status,
            'signature_algorithm': cert.get_signature_algorithm().decode('ascii'),
            'public_key_algorithm': self.get_public_key_algorithm(cert),
            'public_key_bits': self.get_public_key_bits(cert)
        }

    def format_x509_name(self, name):
        components = []
        for key, value in name.get_components():
            components.append(f"{key.decode('ascii')}={value.decode('ascii')}")
        return ', '.join(components)

    def get_public_key_algorithm(self, cert):
        try:
            pk = cert.get_pubkey()
            return pk.type().name
        except:
            return "UNKNOWN"

    def get_public_key_bits(self, cert):
        try:
            pk = cert.get_pubkey()
            return pk.bits()
        except:
            return 0

    def get_certificate_status(self, days_until_expiry):
        thresholds = self.config['alerting']['alert_thresholds']
        
        if days_until_expiry < thresholds['expired']:
            return 'EXPIRED'
        elif days_until_expiry <= thresholds['critical']:
            return 'CRITICAL'
        elif days_until_expiry <= thresholds['warning']:
            return 'WARNING'
        else:
            return 'VALID'

    def save_certificate_info(self, cert_info):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO certificates 
            (domain, port, issuer, subject, not_before, not_after, days_until_expiry, status, signature_algorithm, public_key_algorithm, public_key_bits)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cert_info['domain'],
            cert_info['port'],
            cert_info['issuer'],
            cert_info['subject'],
            cert_info['not_before'],
            cert_info['not_after'],
            cert_info['days_until_expiry'],
            cert_info['status'],
            cert_info['signature_algorithm'],
            cert_info['public_key_algorithm'],
            cert_info['public_key_bits']
        ))
        
        conn.commit()
        conn.close()

    def save_certificate_check(self, domain, port, result, error_message, duration):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO certificate_checks 
            (domain, port, check_result, error_message, check_duration)
            VALUES (?, ?, ?, ?, ?)
        ''', (domain, port, result, error_message, duration))
        
        conn.commit()
        conn.close()

    def check_domains(self, domains, ports=None):
        if ports is None:
            ports = self.config['monitoring']['default_ports']
        
        results = []
        total_domains = len(domains) * len(ports)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.config['monitoring']['max_workers']) as executor:
            futures = []
            
            for domain in domains:
                for port in ports:
                    future = executor.submit(self.get_certificate_info, domain.strip(), port)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.save_certificate_info(result)
                        self.check_and_alert(result)
                    
                    completed += 1
                    progress = (completed / total_domains) * 100
                    print(f"Progress: {progress:.1f}% ({completed}/{total_domains})", end='\r')
                    
                except Exception as e:
                    self.logger.error(f"Error processing domain: {e}")
                    completed += 1
        
        print(f"\n✅ Check completed: {len(results)} certificates processed")
        return results

    def check_and_alert(self, cert_info):
        if cert_info['status'] in ['CRITICAL', 'EXPIRED']:
            self.send_alert(cert_info)

    def send_alert(self, cert_info):
        message = f"""
Certificate Alert - {cert_info['status']}

Domain: {cert_info['domain']}:{cert_info['port']}
Expiry Date: {cert_info['not_after'].strftime('%Y-%m-%d %H:%M:%S')}
Days Until Expiry: {cert_info['days_until_expiry']}
Issuer: {cert_info['issuer']}

This certificate requires immediate attention!
"""

        alert_data = {
            'domain': cert_info['domain'],
            'alert_type': 'CERTIFICATE_EXPIRY',
            'message': message,
            'severity': cert_info['status']
        }

        self.save_alert(alert_data)
        
        threads = []
        
        if self.config['alerting']['smtp']['username']:
            threads.append(threading.Thread(target=self.send_email_alert, args=(cert_info, message)))
        
        if self.config['alerting']['slack_webhook']:
            threads.append(threading.Thread(target=self.send_slack_alert, args=(cert_info, message)))
        
        if self.config['alerting']['discord_webhook']:
            threads.append(threading.Thread(target=self.send_discord_alert, args=(cert_info, message)))
        
        for thread in threads:
            thread.start()

    def save_alert(self, alert_data):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts 
            (domain, alert_type, message, severity)
            VALUES (?, ?, ?, ?)
        ''', (alert_data['domain'], alert_data['alert_type'], alert_data['message'], alert_data['severity']))
        
        conn.commit()
        conn.close()

    def send_email_alert(self, cert_info, message):
        try:
            smtp_config = self.config['alerting']['smtp']
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            
            msg = MimeMultipart()
            msg['From'] = smtp_config['from_email']
            msg['To'] = smtp_config['to_email']
            msg['Subject'] = f"🚨 Certificate Alert: {cert_info['domain']} - {cert_info['status']}"
            
            msg.attach(MimeText(message, 'plain'))
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for {cert_info['domain']}")
        except Exception as e:
            self.logger.error(f"Email alert failed: {e}")

    def send_slack_alert(self, cert_info, message):
        try:
            webhook_url = self.config['alerting']['slack_webhook']
            color = "#ff0000" if cert_info['status'] == 'EXPIRED' else "#ffa500" if cert_info['status'] == 'CRITICAL' else "#ffff00"
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"Certificate Alert: {cert_info['domain']}",
                        "text": message,
                        "fields": [
                            {
                                "title": "Status",
                                "value": cert_info['status'],
                                "short": True
                            },
                            {
                                "title": "Days Until Expiry",
                                "value": cert_info['days_until_expiry'],
                                "short": True
                            }
                        ],
                        "ts": datetime.now().timestamp()
                    }
                ]
            }
            
            requests.post(webhook_url, json=payload, timeout=10)
            self.logger.info(f"Slack alert sent for {cert_info['domain']}")
        except Exception as e:
            self.logger.error(f"Slack alert failed: {e}")

    def send_discord_alert(self, cert_info, message):
        try:
            webhook_url = self.config['alerting']['discord_webhook']
            color = 0xff0000 if cert_info['status'] == 'EXPIRED' else 0xffa500 if cert_info['status'] == 'CRITICAL' else 0xffff00
            
            embed = {
                "title": f"🚨 Certificate Alert: {cert_info['domain']}",
                "description": message,
                "color": color,
                "timestamp": datetime.now().isoformat(),
                "fields": [
                    {
                        "name": "Domain",
                        "value": cert_info['domain'],
                        "inline": True
                    },
                    {
                        "name": "Status",
                        "value": cert_info['status'],
                        "inline": True
                    },
                    {
                        "name": "Days Until Expiry",
                        "value": str(cert_info['days_until_expiry']),
                        "inline": True
                    }
                ]
            }
            
            payload = {"embeds": [embed]}
            requests.post(webhook_url, json=payload, timeout=10)
            self.logger.info(f"Discord alert sent for {cert_info['domain']}")
        except Exception as e:
            self.logger.error(f"Discord alert failed: {e}")

    def generate_report(self, report_type='compliance', output_format='text'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if report_type == 'compliance':
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_certs,
                    SUM(CASE WHEN status = 'EXPIRED' THEN 1 ELSE 0 END) as expired,
                    SUM(CASE WHEN status = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN status = 'WARNING' THEN 1 ELSE 0 END) as warning,
                    SUM(CASE WHEN status = 'VALID' THEN 1 ELSE 0 END) as valid,
                    AVG(days_until_expiry) as avg_days_remaining,
                    MIN(days_until_expiry) as min_days_remaining
                FROM certificates
                WHERE last_checked > datetime('now', '-1 day')
            ''')
            
            stats = cursor.fetchone()
            
            cursor.execute('''
                SELECT domain, days_until_expiry, status, not_after
                FROM certificates
                WHERE status IN ('EXPIRED', 'CRITICAL', 'WARNING')
                ORDER BY days_until_expiry ASC
                LIMIT 20
            ''')
            
            critical_certs = cursor.fetchall()
            
            report_data = {
                'report_type': 'compliance',
                'generated_at': datetime.now().isoformat(),
                'summary': {
                    'total_certificates': stats[0],
                    'expired': stats[1],
                    'critical': stats[2],
                    'warning': stats[3],
                    'valid': stats[4],
                    'avg_days_remaining': round(stats[5] or 0, 2),
                    'min_days_remaining': stats[6] or 0
                },
                'critical_certificates': [
                    {
                        'domain': cert[0],
                        'days_until_expiry': cert[1],
                        'status': cert[2],
                        'expiry_date': cert[3]
                    } for cert in critical_certs
                ]
            }
        
        conn.close()
        
        if output_format == 'json':
            return json.dumps(report_data, indent=2, default=str)
        elif output_format == 'csv':
            csv_output = "domain,days_until_expiry,status,expiry_date\n"
            for cert in report_data['critical_certificates']:
                csv_output += f"{cert['domain']},{cert['days_until_expiry']},{cert['status']},{cert['expiry_date']}\n"
            return csv_output
        else:
            output = f"Certificate Compliance Report\n"
            output += "=" * 50 + "\n"
            output += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            output += f"Total Certificates: {report_data['summary']['total_certificates']}\n"
            output += f"Expired: {report_data['summary']['expired']}\n"
            output += f"Critical: {report_data['summary']['critical']}\n"
            output += f"Warning: {report_data['summary']['warning']}\n"
            output += f"Valid: {report_data['summary']['valid']}\n"
            output += f"Average Days Remaining: {report_data['summary']['avg_days_remaining']}\n"
            output += f"Minimum Days Remaining: {report_data['summary']['min_days_remaining']}\n\n"
            
            output += "Critical Certificates:\n"
            for cert in report_data['critical_certificates']:
                output += f"  {cert['domain']}: {cert['days_until_expiry']} days ({cert['status']})\n"
            
            return output

    def continuous_monitoring(self, interval=3600):
        self.logger.info(f"Starting continuous monitoring with {interval} second interval")
        
        try:
            while True:
                self.logger.info("Starting certificate check cycle")
                
                domains = self.load_domains_from_file('domains.txt')
                if not domains:
                    self.logger.error("No domains found in domains.txt")
                    time.sleep(interval)
                    continue
                
                self.check_domains(domains)
                
                if self.config['reporting']['auto_generate']:
                    report = self.generate_report('compliance', 'text')
                    self.save_report(report)
                
                self.logger.info(f"Check cycle completed. Sleeping for {interval} seconds")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")

    def load_domains_from_file(self, filename):
        if not os.path.exists(filename):
            return []
        
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        return domains

    def save_report(self, report):
        report_dir = self.config['reporting']['report_path']
        os.makedirs(report_dir, exist_ok=True)
        
        filename = f"certificate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(report_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        self.logger.info(f"Report saved: {filepath}")

def main():
    parser = argparse.ArgumentParser(description='Certificate Expiry Checker')
    parser.add_argument('--domain', help='Single domain to check')
    parser.add_argument('--file', default='domains.txt', help='File containing domains to check')
    parser.add_argument('--check', action='store_true', help='Check all domains')
    parser.add_argument('--monitor', action='store_true', help='Continuous monitoring')
    parser.add_argument('--interval', type=int, default=3600, help='Monitoring interval in seconds')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--report-type', default='compliance', help='Type of report to generate')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text', help='Output format')
    parser.add_argument('--warning-days', type=int, default=30, help='Days for warning threshold')
    parser.add_argument('--critical-days', type=int, default=7, help='Days for critical threshold')
    
    args = parser.parse_args()
    
    checker = CertificateChecker()
    
    if args.warning_days != 30 or args.critical_days != 7:
        checker.config['alerting']['alert_thresholds']['warning'] = args.warning_days
        checker.config['alerting']['alert_thresholds']['critical'] = args.critical_days
    
    if args.domain:
        results = checker.check_domains([args.domain])
        for result in results:
            print(f"Domain: {result['domain']}")
            print(f"Status: {result['status']}")
            print(f"Days until expiry: {result['days_until_expiry']}")
            print(f"Expiry date: {result['not_after']}")
            print("-" * 50)
    
    elif args.check:
        domains = checker.load_domains_from_file(args.file)
        if not domains:
            print("No domains found. Add domains to domains.txt file.")
            return
        
        print(f"Checking {len(domains)} domains...")
        results = checker.check_domains(domains)
        
        critical_count = sum(1 for r in results if r['status'] in ['CRITICAL', 'EXPIRED'])
        warning_count = sum(1 for r in results if r['status'] == 'WARNING')
        
        print(f"\n📊 Check Summary:")
        print(f"   Total: {len(results)}")
        print(f"   🔴 Critical/Expired: {critical_count}")
        print(f"   🟡 Warning: {warning_count}")
        print(f"   🟢 Valid: {len(results) - critical_count - warning_count}")
    
    elif args.report:
        report = checker.generate_report(args.report_type, args.format)
        print(report)
    
    elif args.monitor:
        checker.continuous_monitoring(args.interval)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
