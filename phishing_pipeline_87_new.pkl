# app.py
from app6 import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import random
import socket
import threading
import time
import psutil
import json
import pickle
import joblib
import xgboost as xgb
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

# -----------------------
# Flask app init
# -----------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'np2-cybersecurity-otp-email-2025')

def resolve_dns(ip):
    """Try to resolve hostname from IP (reverse DNS)."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

# -----------------------
# Globals
# -----------------------
otp_storage = {}
threat_logs = []
scanning_active = False
scan_results = []

# Blacklist example (simulated)
blacklisted_ips = {
    "192.168.1.100", "10.0.0.1", "203.0.113.0", "198.51.100.255",
    "172.16.0.1", "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "185.220.101.182", "185.220.103.7", "185.220.102.8",
    "malicious-site.com", "phishing-example.net"
}

# -----------------------
# Helper: robust model loader
# -----------------------
def load_pickle_or_joblib(path):
    """
    Try joblib.load -> pickle.load -> xgboost.Booster().load_model
    Returns (model_object, loader_type_string)
    """
    if not os.path.exists(path):
        return None, None
    try:
        # Try joblib
        model = joblib.load(path)
        return model, "joblib"
    except Exception:
        pass
    try:
        # Try pickle
        with open(path, "rb") as f:
            model = pickle.load(f)
            return model, "pickle"
    except Exception:
        pass
    try:
        # Try xgboost native booster
        booster = xgb.Booster()
        booster.load_model(path)
        return booster, "xgboost_booster"
    except Exception:
        pass
    return None, None

def predict_with_model(model, loader_type, X):
    """
    Accepts:
      - model: object returned from loader
      - loader_type: one of "joblib","pickle","xgboost_booster"
      - X: numpy array or pandas DataFrame
    Returns:
      - probability_or_score (float between 0 and 1) or array if model returns array
    """
    if model is None:
        raise ValueError("Model is None")
    try:
        # xgboost booster expects DMatrix
        if loader_type == "xgboost_booster" and isinstance(model, xgb.Booster):
            dmat = xgb.DMatrix(X)
            preds = model.predict(dmat)
            # For binary classification booster may return probability (shape [n_samples])
            return preds
        # sklearn-like
        if hasattr(model, "predict_proba"):
            # Ensure X is 2D
            if isinstance(X, np.ndarray):
                arr = X
            else:
                arr = np.array(X)
            proba = model.predict_proba(arr)
            # return probability of positive class (assume class 1 index is last)
            if proba.ndim == 2 and proba.shape[1] >= 2:
                return proba[:, 1]
            # fallback: return proba[:,0]
            return proba[:, 0]
        # model has predict (decision_function) fallback
        if hasattr(model, "predict"):
            preds = model.predict(np.array(X))
            # try to map to 0/1 or probability
            return preds
        # Unknown model interface
        raise RuntimeError("Unsupported model type for prediction")
    except Exception as e:
        # bubble up
        raise

# -----------------------
# Load models at startup
# -----------------------
PHISHING_MODEL_PATH = os.path.join(os.getcwd(), "phishing_pipeline_87_new.pkl")
NETWORK_MODEL_PATH = os.path.join(os.getcwd(), "best_model.pkl")

phishing_model, phishing_loader = load_pickle_or_joblib(PHISHING_MODEL_PATH)
network_model, network_loader = load_pickle_or_joblib(NETWORK_MODEL_PATH)

phishing_model_loaded = phishing_model is not None
network_model_loaded = network_model is not None

print("=== Model status ===")
print(f"phishing_xgb_model.pkl loaded: {phishing_model_loaded} (loader={phishing_loader})")
print(f"best_model.pkl loaded: {network_model_loaded} (loader={network_loader})")
print("====================")

# -----------------------
# Feature names / extractors
# -----------------------
# For network model we reuse your long previously-provided list (63 features)
network_feature_names = [
    "source_port","destination_port","dur","sbytes","dbytes","sttl","dttl","sloss","dloss","sload","dload","spkts","dpkts","swin","dwin","stcpb","dtcpb","smeansz","dmeansz","trans_depth","res_bdy_len","sjit","djit","stime","ltime","sintpkt","dintpkt","tcprtt","synack","ackdat","is_sm_ips_ports","ct_state_ttl","ct_flw_http_mthd","is_ftp_login","ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","protocol_tcp","protocol_udp","state_ACC","state_CLO","state_CON","state_FIN","state_INT","state_REQ","state_RST","service_dhcp","service_dns","service_ftp","service_ftp-data","service_http","service_irc","service_pop3","service_radius","service_smtp","service_snmp","service_ssh","service_ssl"
]

# For phishing model: compute common URL features (this is a best-effort set).
# IMPORTANT: If your phishing model expects different features/order, update this list to match.
url_feature_names = [
    "url_length",
    "hostname_length",
    "count_dots",
    "count_hyphen",
    "count_at",
    "count_qmark",
    "count_equal",
    "count_slash",
    "has_ip",           # 0 or 1
    "count_digits",
    "ratio_digits",     # digits / length
    "has_https",
    "count_subdomains"  # number of dots in hostname - 1
]

# -----------------------
# URL (phishing) feature extractor
# -----------------------
def extract_url_features(url):
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        url_str = (parsed.scheme + "://" + parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")) if parsed.netloc else url

        # features
        url_length = len(url_str)
        hostname_length = len(hostname)
        count_dots = url_str.count('.')
        count_hyphen = url_str.count('-')
        count_at = url_str.count('@')
        count_qmark = url_str.count('?')
        count_equal = url_str.count('=')
        count_slash = url_str.count('/')
        count_digits = sum(c.isdigit() for c in url_str)
        ratio_digits = (count_digits / url_length) if url_length > 0 else 0.0
        has_https = 1 if url_str.lower().startswith("https") else 0

        # check for IP in hostname
        has_ip = 0
        try:
            if hostname:
                parts = hostname.split('.')
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    has_ip = 1
                else:
                    # try socket gethostbyname to see if hostname resolves to an IP-looking string
                    resolved = socket.gethostbyname(hostname)
                    # if hostname resolves to something like '127.0.0.1' treat as ip-based host
                    if resolved and all(p.isdigit() for p in resolved.split('.')):
                        has_ip = 1
        except Exception:
            has_ip = 0

        # subdomains count
        count_subdomains = hostname.count('.') - 1 if hostname.count('.') > 0 else 0

        feature_vector = [
            url_length,
            hostname_length,
            count_dots,
            count_hyphen,
            count_at,
            count_qmark,
            count_equal,
            count_slash,
            int(has_ip),
            count_digits,
            ratio_digits,
            has_https,
            count_subdomains
        ]
        return np.array(feature_vector).reshape(1, -1), hostname
    except Exception as e:
        print(f"[extract_url_features] error: {e}")
        return np.zeros((1, len(url_feature_names))), ""

# -----------------------
# Network feature extractor (your original logic adapted)
# -----------------------
def extract_network_features(network_data):
    """
    network_data is expected to be a dict with keys similar to earlier code.
    Returns: numpy array shaped (1, n_features) according to network_feature_names
    """
    features = {}
    # Basic network features
    features['source_port'] = int(network_data.get('source_port', 0))
    features['destination_port'] = int(network_data.get('dest_port', network_data.get('destination_port', 80)))
    features['dur'] = float(network_data.get('duration', 0))
    features['sbytes'] = int(network_data.get('source_bytes', 0))
    features['dbytes'] = int(network_data.get('dest_bytes', 0))
    features['sttl'] = int(network_data.get('source_ttl', 64))
    features['dttl'] = int(network_data.get('dest_ttl', 64))
    features['sloss'] = int(network_data.get('source_loss', 0))
    features['dloss'] = int(network_data.get('dest_loss', 0))
    features['sload'] = float(network_data.get('source_load', 0))
    features['dload'] = float(network_data.get('dest_load', 0))
    features['spkts'] = int(network_data.get('source_packets', 0))
    features['dpkts'] = int(network_data.get('dest_packets', 0))
    features['swin'] = int(network_data.get('source_window', 0))
    features['dwin'] = int(network_data.get('dest_window', 0))
    features['stcpb'] = int(network_data.get('source_tcp_base', 0))
    features['dtcpb'] = int(network_data.get('dest_tcp_base', 0))
    features['smeansz'] = float(network_data.get('source_mean_size', 0))
    features['dmeansz'] = float(network_data.get('dest_mean_size', 0))
    features['trans_depth'] = int(network_data.get('trans_depth', 0))
    features['res_bdy_len'] = int(network_data.get('response_body_len', 0))

    # Jitter and timing features
    features['sjit'] = float(network_data.get('source_jitter', 0))
    features['djit'] = float(network_data.get('dest_jitter', 0))
    features['stime'] = float(network_data.get('start_time', 0))
    features['ltime'] = float(network_data.get('last_time', 0))
    features['sintpkt'] = float(network_data.get('source_inter_packet_time', 0))
    features['dintpkt'] = float(network_data.get('dest_inter_packet_time', 0))
    features['tcprtt'] = float(network_data.get('tcp_rtt', 0))
    features['synack'] = float(network_data.get('syn_ack_time', 0))
    features['ackdat'] = float(network_data.get('ack_data_time', 0))

    # Connection tracking features
    features['is_sm_ips_ports'] = int(network_data.get('same_ip_port', 0))
    features['ct_state_ttl'] = int(network_data.get('ct_state_ttl', 0))
    features['ct_flw_http_mthd'] = int(network_data.get('ct_flow_http_method', 0))
    features['is_ftp_login'] = int(network_data.get('is_ftp_login', 0))
    features['ct_ftp_cmd'] = int(network_data.get('ct_ftp_cmd', 0))
    features['ct_srv_src'] = int(network_data.get('ct_srv_src', 0))
    features['ct_srv_dst'] = int(network_data.get('ct_srv_dst', 0))
    features['ct_dst_ltm'] = int(network_data.get('ct_dst_ltm', 0))
    features['ct_src_ltm'] = int(network_data.get('ct_src_ltm', 0))
    features['ct_src_dport_ltm'] = int(network_data.get('ct_src_dport_ltm', 0))
    features['ct_dst_sport_ltm'] = int(network_data.get('ct_dst_sport_ltm', 0))
    features['ct_dst_src_ltm'] = int(network_data.get('ct_dst_src_ltm', 0))

    # Protocol features (one-hot encoded)
    protocol = network_data.get('protocol', 'tcp').lower()
    features['protocol_tcp'] = 1 if protocol == 'tcp' else 0
    features['protocol_udp'] = 1 if protocol == 'udp' else 0

    # State features (one-hot encoded)
    state = network_data.get('state', '').upper()
    features['state_ACC'] = 1 if state == 'ACC' else 0
    features['state_CLO'] = 1 if state == 'CLO' else 0
    features['state_CON'] = 1 if state == 'CON' else 0
    features['state_FIN'] = 1 if state == 'FIN' else 0
    features['state_INT'] = 1 if state == 'INT' else 0
    features['state_REQ'] = 1 if state == 'REQ' else 0
    features['state_RST'] = 1 if state == 'RST' else 0

    # Service features (one-hot encoded) based on destination port
    port = features['destination_port']
    features['service_dhcp'] = 1 if port in [67, 68] else 0
    features['service_dns'] = 1 if port == 53 else 0
    features['service_ftp'] = 1 if port == 21 else 0
    # use valid python name for service_ftp-data -> service_ftp_data
    features['service_ftp-data'] = 1 if port == 20 else 0
    features['service_http'] = 1 if port in [80, 8080] else 0
    features['service_irc'] = 1 if port in [6667, 6668, 6669] else 0
    features['service_pop3'] = 1 if port == 110 else 0
    features['service_radius'] = 1 if port in [1812, 1813] else 0
    features['service_smtp'] = 1 if port == 25 else 0
    features['service_snmp'] = 1 if port == 161 else 0
    features['service_ssh'] = 1 if port == 22 else 0
    features['service_ssl'] = 1 if port == 443 else 0

    # Build feature vector in correct order
    feature_vector = []
    for name in network_feature_names:
        feature_vector.append(features.get(name, 0))
    return np.array(feature_vector).reshape(1, -1)

# -----------------------
# Threat classification util (similar to your prior classify_threat_level)
# -----------------------
def classify_threat_level(threat_probability, network_data=None, threat_factors=None):
    if threat_probability is None:
        threat_probability = 0.0

    if threat_probability < 0.3:
        return {
            "threat_detected": False,
            "threat_type": "Normal Traffic",
            "threat_level": "Safe",
            "risk_score": int(threat_probability * 100),
            "threat_description": "No threats detected. Network traffic appears normal.",
            "threat_factors": threat_factors or [],
            "recommendations": ["Continue monitoring"],
            "color_code": "#22c55e",
            "icon": "✅"
        }

    if threat_probability >= 0.9:
        threat_level = "Critical"
        threat_type = "Critical Security Threat"
        color_code = "#991b1b"
        icon = "🚨"
        recommendations = [
            "IMMEDIATE ACTION REQUIRED",
            "Block source IP immediately",
            "Investigate network logs",
            "Contact security team"
        ]
    elif threat_probability >= 0.7:
        threat_level = "High"
        threat_type = "High Risk Activity"
        color_code = "#ef4444"
        icon = "⚠️"
        recommendations = [
            "High priority investigation required",
            "Monitor closely",
            "Review firewall rules"
        ]
    elif threat_probability >= 0.5:
        threat_level = "Medium"
        threat_type = "Medium Risk Activity"
        color_code = "#f59e0b"
        icon = "⚡"
        recommendations = [
            "Monitor for escalation",
            "Review access logs"
        ]
    else:
        threat_level = "Low"
        threat_type = "Low Risk Activity"
        color_code = "#eab308"
        icon = "⚠️"
        recommendations = [
            "Continue monitoring",
        ]

    threat_description = f"Threat probability: {threat_probability:.2f}. " + (", ".join(threat_factors) if threat_factors else "")

    return {
        "threat_detected": True,
        "threat_type": threat_type,
        "threat_level": threat_level,
        "risk_score": int(threat_probability * 100),
        "threat_description": threat_description,
        "threat_factors": threat_factors or [],
        "recommendations": recommendations,
        "color_code": color_code,
        "icon": icon
    }

# -----------------------
# Email service (use EMAIL_USER/EMAIL_PASSWORD env vars)
# -----------------------
class EmailService:
    def __init__(self):
        self.smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.email_user = os.environ.get('EMAIL_USER')
        self.email_password = os.environ.get('EMAIL_PASSWORD')

        if not self.email_user or not self.email_password:
            print("⚠️ Email not configured. OTPs and alerts will be printed to console.")

    def send_otp(self, email, otp):
        try:
            if not self.email_user or not self.email_password:
                print(f"📧 OTP for {email}: {otp} (printed because email not configured)")
                return True

            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = email
            msg['Subject'] = "🔐 NP² Cybersecurity - Your Login OTP"
            body = f"Your OTP: {otp}\nValid 10 minutes."
            msg.attach(MIMEText(body, 'plain'))
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            server.send_message(msg)
            server.quit()
            print(f"✅ OTP sent to {email}")
            return True
        except Exception as e:
            print(f"❌ send_otp error: {e}")
            print(f"📧 OTP for {email}: {otp} (printed due to error)")
            return True

    def send_threat_alert(self, email, threat_data):
        try:
            if not self.email_user or not self.email_password:
                print(f"🚨 Threat Alert for {email}: {json.dumps(threat_data, default=str)}")
                return True

            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = email
            msg['Subject'] = f"🚨 {threat_data.get('threat_level', 'UNKNOWN')} THREAT - NP² Cybersecurity"
            body = f"Threat: {threat_data.get('threat_description','')}\nRisk: {threat_data.get('risk_score',0)}"
            msg.attach(MIMEText(body, 'plain'))
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            server.send_message(msg)
            server.quit()
            print(f"🚨 Threat alert sent to {email}")
            return True
        except Exception as e:
            print(f"❌ send_threat_alert error: {e}")
            return False

email_service = EmailService()

# -----------------------
# Network scan & simulation (live)
# -----------------------
def scan_network_connections():
    connections = []
    try:
        net_connections = psutil.net_connections(kind='inet')
        for conn in net_connections:
            if conn.raddr:
                src_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
                dst_ip = conn.raddr.ip
                connection_data = {
                    "source_ip": src_ip,
                    "source_dns": resolve_dns(src_ip),         # DNS-enriched
                    "source_port": conn.laddr.port if conn.laddr else 0,
                    "destination_ip": dst_ip,
                    "destination_dns": resolve_dns(dst_ip),    # DNS-enriched
                    "dest_port": conn.raddr.port,
                    "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "status": conn.status,
                    "duration": random.uniform(0.1, 5.0),
                    "source_bytes": random.randint(100, 10000),
                    "dest_bytes": random.randint(100, 5000),
                    "timestamp": datetime.now().isoformat()
                }
                # ML/model/heuristics analysis
                try:
                    features = extract_network_features(connection_data)
                    prob = None
                    used_model = False
                    if network_model_loaded:
                        preds = predict_with_model(network_model, network_loader, features)
                        prob = float(preds[0]) if hasattr(preds, "__len__") else float(preds)
                        used_model = True
                    else:
                        prob = 0.8 if (dst_ip in blacklisted_ips or src_ip in blacklisted_ips) else random.uniform(0.0, 0.6)
                    classification = classify_threat_level(prob, network_data=connection_data)
                    classification.update({
                        "confidence": prob if prob else 0.0,
                        "threat_probability": prob,
                        "model_used": used_model
                    })
                    connection_data.update(classification)
                except Exception as e:
                    print(f"[scan_network_connections] analysis error: {e}")
                connections.append(connection_data)
    except Exception as e:
        print(f"[scan_network_connections] error: {e}")
    return connections


# -----------------------
# Flask routes (auth + OTP)
# -----------------------
@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    otp = str(random.randint(100000, 999999))
    otp_storage[email] = {
        "otp": otp,
        "expires": datetime.now() + timedelta(minutes=10),
        "attempts": 0
    }
    email_service.send_otp(email, otp)
    return jsonify({"success": True, "message": f"OTP sent to {email}. Check inbox (or console if email not configured)."})


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    stored = otp_storage.get(email)
    if not stored:
        return jsonify({"success": False, "message": "No OTP found. Request a new one."}), 400
    if datetime.now() > stored["expires"]:
        del otp_storage[email]
        return jsonify({"success": False, "message": "OTP expired. Request a new one."}), 400
    stored["attempts"] += 1
    if stored["attempts"] > 3:
        del otp_storage[email]
        return jsonify({"success": False, "message": "Too many attempts. Request a new OTP."}), 400
    if stored["otp"] != otp:
        return jsonify({"success": False, "message": f"Invalid OTP. {4 - stored['attempts']} attempts remaining."}), 400
    session['user_email'] = email
    session['login_time'] = datetime.now().isoformat()
    del otp_storage[email]
    return jsonify({"success": True, "message": "Login successful."})

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', user_email=session['user_email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# -----------------------
# Analyze URL (phishing) - uses phishing model
# -----------------------
def extract_ip_from_url(url):
    try:
        parsed = urlparse(url if url.startswith(("http://","https://")) else "http://" + url)
        hostname = parsed.hostname
        if hostname:
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                ip = None
            return ip, hostname
        return None, None
    except Exception as e:
        print(f"[extract_ip_from_url] {e}")
        return None, None

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        ip_address, hostname = extract_ip_from_url(url)
        features, hostname_used = extract_url_features(url)
        prob = None
        used_model = False
        if phishing_model_loaded:
            preds = predict_with_model(phishing_model, phishing_loader, features)
            if hasattr(preds, "__len__"):
                prob = float(preds[0])
            else:
                prob = float(preds)
            used_model = True
        else:
            # fallback heuristics
            threat_factors = []
            if hostname and (hostname in blacklisted_ips or ip_address in blacklisted_ips):
                threat_factors.append("Blacklisted host/IP")
            if url.count('@') > 0:
                threat_factors.append("Contains @")
            if len(url) > 100:
                threat_factors.append("Long URL")
            prob = 0.8 if threat_factors else random.uniform(0.0, 0.6)
        classification = classify_threat_level(prob, threat_factors=threat_factors if 'threat_factors' in locals() else None)
        result = {
            "url": url,
            "hostname": hostname,
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "analysis_type": "URL Analysis",
            "model_used": used_model,
            "threat_probability": prob,
            **classification
        }
        threat_logs.append(result)
        # send alert if high risk
        if result.get('threat_detected') and result.get('risk_score',0) >= 70:
            email_service.send_threat_alert(session['user_email'], result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

# -----------------------
# Manual analysis (network) - uses network model
# -----------------------
@app.route('/manual_analysis', methods=['POST'])
def manual_analysis():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json()
    try:
        analysis_data = {
            "source_ip": data.get('source_ip'),
            "destination_ip": data.get('destination_ip'),
            "protocol": data.get('protocol', 'tcp').lower(),
            "duration": float(data.get('duration', 1.0)),
            "source_port": int(data.get('source_port', 0)),
            "dest_port": int(data.get('dest_port', 80)),
            "source_bytes": int(data.get('source_bytes', 1024)),
            "dest_bytes": int(data.get('dest_bytes', 512))
        }
        features = extract_network_features(analysis_data)
        prob = None
        used_model = False
        if network_model_loaded:
            preds = predict_with_model(network_model, network_loader, features)
            if hasattr(preds, "__len__"):
                prob = float(preds[0])
            else:
                prob = float(preds)
            used_model = True
        else:
            # fallback
            prob = 0.9 if (analysis_data['destination_ip'] in blacklisted_ips or analysis_data['source_ip'] in blacklisted_ips) else random.uniform(0.0, 0.6)
        classification = classify_threat_level(prob)
        result = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": "Manual Analysis",
            "model_used": used_model,
            "threat_probability": prob,
            **classification,
            **analysis_data
        }
        threat_logs.append(result)
        if result.get('threat_detected') and result.get('risk_score',0) >= 70:
            email_service.send_threat_alert(session['user_email'], result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

# -----------------------
# Live scanning endpoints (uses network model)
# -----------------------
@app.route('/start_live_scan', methods=['POST'])
def start_live_scan():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    global scanning_active
    scanning_active = True

    def background_scan():
        global scan_results
        while scanning_active:
            connections = scan_network_connections()
            scan_results = connections[-50:]
            # send alerts for high risk
            for conn in connections:
                if conn.get('threat_detected') and conn.get('risk_score',0) >= 70:
                    email_service.send_threat_alert(session['user_email'], conn)
            time.sleep(3)
    scan_thread = threading.Thread(target=background_scan, daemon=True)
    scan_thread.start()
    return jsonify({"success": True, "message": "Live scanning started"})

@app.route('/stop_live_scan', methods=['POST'])
def stop_live_scan():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    global scanning_active
    scanning_active = False
    return jsonify({"success": True, "message": "Live scanning stopped"})

@app.route('/get_scan_results')
def get_scan_results():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({
        "scanning_active": scanning_active,
        "results": scan_results,
        "total_connections": len(scan_results),
        "threats_detected": len([r for r in scan_results if r.get('threat_detected')])
    })

# -----------------------
# Report download
# -----------------------
@app.route('/download_report')
def download_report():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    import io
    output = io.StringIO()
    if scan_results:
        output.write("Timestamp,Source IP,Destination IP,Protocol,Port,Threat Detected,Threat Level,Threat Type,Risk Score,Confidence,Description\n")
        for result in scan_results:
            desc = (result.get("threat_description","") or "").replace('"','""')
            output.write(f'"{result.get("timestamp","")}",')
            output.write(f'"{result.get("source_ip","")}",')
            output.write(f'"{result.get("destination_ip","")}",')
            output.write(f'"{result.get("protocol","")}",')
            output.write(f'"{result.get("dest_port","")}",')
            output.write(f'"{result.get("threat_detected","")}",')
            output.write(f'"{result.get("threat_level","")}",')
            output.write(f'"{result.get("threat_type","")}",')
            output.write(f'"{result.get("risk_score","")}",')
            output.write(f'"{result.get("confidence","")}",')
            output.write(f'"{desc}"\n')
    report_content = output.getvalue()
    output.close()
    return jsonify({
        "filename": f"np2_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        "content": report_content
    })

# -----------------------
# Dashboard stats
# -----------------------
@app.route('/get_dashboard_stats')
def get_dashboard_stats():
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    total_threats = len([log for log in threat_logs if log.get('threat_detected')])
    high_risk_threats = len([log for log in threat_logs if log.get('risk_score', 0) >= 70])
    return jsonify({
        "total_threats": total_threats,
        "high_risk_threats": high_risk_threats,
        "total_scans": len(threat_logs),
        "scanning_active": scanning_active,
        "phishing_model_loaded": phishing_model_loaded,
        "network_model_loaded": network_model_loaded,
        "recent_threats": threat_logs[-10:] if threat_logs else []
    })

# -----------------------
# Run
# -----------------------
if __name__ == '__main__':
    print("🛡️ NP² Cybersecurity - dual-model Flask app")
    if phishing_model_loaded:
        print(f"✅ phishing model loaded ({phishing_loader})")
        print(f"📊 url feature count: {len(url_feature_names)}")
    else:
        print("⚠️ phishing model not loaded - URL analysis will use heuristics")

    if network_model_loaded:
        print(f"✅ network model loaded ({network_loader})")
        print(f"📊 network feature count: {len(network_feature_names)}")
    else:
        print("⚠️ network model not loaded - network analysis will use heuristics/simulation")

    print("🌐 Server: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
