#!/usr/bin/env python3
import sys
import json
import requests
import time
import os
import hashlib
from datetime import datetime
import pytz

# Telegram Configuration
TELEGRAM_BOT_TOKEN = ""  # Your Telegram Bot Token
CHAT_ID = ""  # Your Telegram Chat ID

# Rate limiting configuration
CACHE_FILE = "/var/ossec/tmp/telegram_malware_alerts.json"
MIN_DELAY_SECONDS = 0  # Minimum time between messages for same hash
MAX_ALERTS_PER_MINUTE = 20  # Maximum alerts per minute

# Malware-specific rule IDs that should trigger notifications
MALWARE_RULE_IDS = [
    "87101",  # VirusTotal malware detection
    "87102",  # VirusTotal suspicious file
    "87103",  # VirusTotal high confidence malware
    "554",    # File added to the system
    "597",    # Virus detected
    "598",    # Virus removed
    "100201", # User interpretation: "add file" (Original script comment: "VirusTotal malware detection")
    "87105",  
    "553",    
    "100092",
]

def load_alert_cache():
    """Load alert cache to prevent spam"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {'alerts': [], 'last_cleanup': time.time()}
    return {'alerts': [], 'last_cleanup': time.time()}

def save_alert_cache(cache_data):
    """Save alert cache"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f)
    except Exception as e:
        sys.stderr.write(f"Error saving cache: {str(e)}\n")

def cleanup_old_alerts(cache_data):
    """Remove alerts older than 1 hour"""
    current_time = time.time()
    cache_data['alerts'] = [
        alert for alert in cache_data['alerts'] 
        if current_time - alert['timestamp'] < 3600  # 1 hour
    ]
    cache_data['last_cleanup'] = current_time

def should_send_alert(file_hash, cache_data):
    """Check if we should send alert based on rate limiting"""
    current_time = time.time()
    
    # Cleanup old alerts if needed
    if current_time - cache_data['last_cleanup'] > 300:  # 5 minutes
        cleanup_old_alerts(cache_data)
    
    # Check if same hash was alerted recently (within 10 minutes)
    for alert in cache_data['alerts']:
        if alert['hash'] == file_hash and current_time - alert['timestamp'] < 600:
            return False
    
    # Check rate limiting (max alerts per minute)
    recent_alerts = [
        alert for alert in cache_data['alerts']
        if current_time - alert['timestamp'] < 60
    ]
    
    if len(recent_alerts) >= MAX_ALERTS_PER_MINUTE:
        return False
    
    return True

def extract_file_info(alert_json):
    """Extract file information from Wazuh alert"""
    file_info = {}
    
    # Try to get file hash
    if 'data' in alert_json:
        data = alert_json['data']
        # Common hash fields in Wazuh alerts
        for hash_field in ['md5', 'sha1', 'sha256', 'hash']:
            if hash_field in data:
                file_info['hash'] = data[hash_field]
                file_info['hash_type'] = hash_field.upper()
                break
    
    return file_info

def extract_virustotal_info(alert_json):
    """Extract VirusTotal information from alert"""
    vt_info = {}
    
    if 'data' in alert_json:
        data = alert_json['data']
        vt_info['positives'] = data.get('positives', 'N/A')
        vt_info['total'] = data.get('total', 'N/A')
        vt_info['permalink'] = data.get('permalink', '')
        vt_info['scan_date'] = data.get('scan_date', 'N/A')
        
        # Extract malware names
        if 'scans' in data:
            malware_names = []
            scans = data['scans'] if isinstance(data['scans'], dict) else {}
            for engine, result in scans.items():
                if isinstance(result, dict) and result.get('detected'):
                    malware_names.append(f"{engine}: {result.get('result', 'Detected')}")
            vt_info['malware_names'] = malware_names[:5]  # Limit to first 5
    
    return vt_info

def format_telegram_message(alert_json, file_info, vt_info):
    """Format the Telegram message for malware alerts"""
    
    # Get basic alert info
    rule_id = alert_json.get('rule', {}).get('id', 'N/A')
    rule_level = alert_json.get('rule', {}).get('level', 'N/A')
    description = alert_json.get('rule', {}).get('description', 'N/A')
    agent = alert_json.get('agent', {}).get('name', 'N/A')
    
    # Get Wazuh timestamp and convert to WIB
    wazuh_timestamp = alert_json.get('timestamp', '')
    
    # Try multiple possible timestamp fields and formats
    possible_timestamps = [
        alert_json.get('timestamp'),
        alert_json.get('@timestamp'),
        alert_json.get('time'),
        alert_json.get('date')
    ]
    
    timestamp_wib = "N/A"
    
    for ts in possible_timestamps:
        if ts:
            try:
                # Handle different timestamp formats
                if isinstance(ts, str):
                    # Remove milliseconds if present (e.g., 2024-01-01T12:00:00.123Z)
                    if '.' in ts and ts.endswith('Z'):
                        ts = ts.split('.')[0] + 'Z'
                    
                    # Handle Z suffix (UTC)
                    if ts.endswith('Z'):
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    # Handle +00:00 suffix
                    elif '+' in ts or ts.endswith('UTC'):
                        dt = datetime.fromisoformat(ts.replace('UTC', ''))
                    # Handle format like "2024-01-01 12:00:00"
                    elif ' ' in ts and len(ts) >= 19:
                        dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
                        dt = pytz.UTC.localize(dt)  # Assume UTC if no timezone
                    # Handle ISO format without timezone
                    else:
                        dt = datetime.fromisoformat(ts)
                        if dt.tzinfo is None:
                            dt = pytz.UTC.localize(dt)  # Assume UTC if no timezone
                elif isinstance(ts, (int, float)):
                    # Handle Unix timestamp
                    dt = datetime.fromtimestamp(ts, tz=pytz.UTC)
                else:
                    continue
                
                # Convert to WIB (UTC+7)
                wib = pytz.timezone('Asia/Jakarta')
                wib_time = dt.astimezone(wib)
                timestamp_wib = wib_time.strftime("%Y-%m-%d %H:%M:%S WIB")
                break  # Successfully parsed, exit loop
                
            except Exception as e:
                # Debug: uncomment next line to see parsing errors
                # sys.stderr.write(f"Timestamp parse error for '{ts}': {str(e)}\n")
                continue
    
    # If still N/A, use current time in WIB as fallback
    if timestamp_wib == "N/A":
        wib = pytz.timezone('Asia/Jakarta')
        current_wib = datetime.now(wib)
        timestamp_wib = current_wib.strftime("%Y-%m-%d %H:%M:%S WIB")
    
    # Determine severity emoji
    severity_emoji = "🔴"  # Default high severity
    if rule_level <= 5:
        severity_emoji = "🟡"
    elif rule_level <= 10:
        severity_emoji = "🟠"
    
    # Build message
    message = f"{severity_emoji} **MALWARE DETECTED** {severity_emoji}\n\n"
    message += f"🕐 **Time:** {timestamp_wib}\n"
    message += f"🖥️ **Agent:** `{agent}`\n"
    message += f"🔢 **Rule ID:** {rule_id} (Level {rule_level})\n"
    message += f"📝 **Description:** {description}\n\n"
    
    # Add file hash information only (removed file path)
    if file_info.get('hash'):
        message += f"🔐 **{file_info.get('hash_type', 'Hash')}:** `{file_info['hash']}`\n"
    
    # Add VirusTotal information
    if vt_info.get('positives') != 'N/A':
        message += f"\n🛡️ **VirusTotal Results:**\n"
        message += f"  • Detections: {vt_info['positives']}/{vt_info['total']}\n"
        
        if vt_info.get('scan_date') != 'N/A':
            message += f"  • Scan Date: {vt_info['scan_date']}\n"
        
        if vt_info.get('malware_names'):
            message += f"  • Threats Detected:\n"
            for name in vt_info['malware_names']:
                message += f"    - {name}\n"
        
        if vt_info.get('permalink'):
            message += f"  • [View Full Report]({vt_info['permalink']})\n"
    
    # Add action recommendations
    message += f"\n⚠️ **Recommended Actions:**\n"
    message += f"• Isolate the affected system\n"
    message += f"• Run full antivirus scan\n"
    message += f"• Check for IOCs on other systems\n"
    message += f"• Review system logs for suspicious activity\n"
    
    return message

def send_telegram_message(message):
    """Send message to Telegram"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    payload = {
        'chat_id': CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown',
        'disable_web_page_preview': True
    }
    
    try:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"Error sending Telegram message: {str(e)}\n")
        return False

def is_malware_alert(alert_json):
    """Check if this is a malware-related alert"""
    rule_id = str(alert_json.get('rule', {}).get('id', ''))
    description = alert_json.get('rule', {}).get('description', '').lower()
    
    # Check if rule ID is in our malware rule list
    if rule_id in MALWARE_RULE_IDS:
        return True
    
    # Check for malware-related keywords in description
    malware_keywords = [
        'malware', 'virus', 'trojan', 'worm', 'ransomware',
        'virustotal', 'suspicious file', 'threat detected',
        'malicious', 'infected', 'backdoor', 'rootkit'
    ]
    
    return any(keyword in description for keyword in malware_keywords)

def main():
    # Validate arguments
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: script.py alert_file\n")
        sys.exit(1)
    
    # Validate configuration
    if not TELEGRAM_BOT_TOKEN or not CHAT_ID:
        sys.stderr.write("Error: TELEGRAM_BOT_TOKEN and CHAT_ID must be configured\n")
        sys.exit(1)
    
    try:
        # Read the alert file
        with open(sys.argv[1], 'r') as f:
            alert_json = json.load(f)
        
        # Check if this is a malware alert
        if not is_malware_alert(alert_json):
            sys.exit(0)  # Not a malware alert, exit silently
        
        # Load cache for rate limiting
        cache_data = load_alert_cache()
        
        # Extract file information
        file_info = extract_file_info(alert_json)
        file_hash = file_info.get('hash', f"alert_{int(time.time())}")
        
        # Check if we should send this alert
        if not should_send_alert(file_hash, cache_data):
            sys.exit(0)  # Skip due to rate limiting
        
        # Extract VirusTotal information
        vt_info = extract_virustotal_info(alert_json)
        
        # Format and send message
        message = format_telegram_message(alert_json, file_info, vt_info)
        
        if send_telegram_message(message):
            # Update cache
            cache_data['alerts'].append({
                'hash': file_hash,
                'timestamp': time.time()
            })
            save_alert_cache(cache_data)
            
            print(f"Malware alert sent successfully for hash: {file_hash}")
        else:
            sys.stderr.write("Failed to send Telegram message\n")
            sys.exit(1)
            
    except FileNotFoundError:
        sys.stderr.write(f"Error: Alert file not found: {sys.argv[1]}\n")
        sys.exit(1)
    except json.JSONDecodeError:
        sys.stderr.write("Error: Invalid JSON in alert file\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {str(e)}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()