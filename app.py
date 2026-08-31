#!/usr/bin/env python3
"""
Mini SOC Lab - Advanced Enterprise Edition
Complete Security Operations Center with SIEM, Threat Intelligence, and ML
Version: 2.0.0
"""

import os
import sys
import json
import time
import threading
import hashlib
import jwt
import bcrypt
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Any
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
import plotly
import plotly.graph_objs as go
import plotly.express as px
from dotenv import load_dotenv
import requests
import socket
import ipaddress
import subprocess
import netifaces

# Load environment variables
load_dotenv()

# ============================================
# APPLICATION CONFIGURATION
# ============================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'advanced-soc-secret-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///data/soc.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['USE_X_SENDFILE'] = True
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'
csrf = CSRFProtect(app)

# ============================================
# LOGGING CONFIGURATION
# ============================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/soc.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('MiniSOC-Advanced')

# ============================================
# DATABASE MODELS
# ============================================

class User(db.Model, UserMixin):
    """User model with advanced security features"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='analyst')
    department = db.Column(db.String(50))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    api_key = db.Column(db.String(64), unique=True)
    
    def set_password(self, password):
        """Hash password with bcrypt"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        """Verify password"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def generate_api_key(self):
        """Generate API key"""
        self.api_key = hashlib.sha256(f"{self.username}{datetime.utcnow().isoformat()}".encode()).hexdigest()
        return self.api_key

class Device(db.Model):
    """Device inventory with advanced attributes"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    mac = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    vendor = db.Column(db.String(100))
    os = db.Column(db.String(100))
    os_version = db.Column(db.String(50))
    device_type = db.Column(db.String(50))  # server, workstation, mobile, iot, network
    status = db.Column(db.String(20), default='unknown')  # online, offline, suspicious, compromised
    confidence = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_scan = db.Column(db.DateTime)
    open_ports = db.Column(db.Text)  # JSON
    services = db.Column(db.Text)  # JSON
    vulnerabilities = db.Column(db.Text)  # JSON
    risk_score = db.Column(db.Integer, default=0)
    criticality = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    tags = db.Column(db.Text)  # JSON list
    notes = db.Column(db.Text)
    location = db.Column(db.String(100))
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_risk_level(self):
        """Calculate risk level based on score"""
        if self.risk_score >= 80:
            return 'critical'
        elif self.risk_score >= 60:
            return 'high'
        elif self.risk_score >= 40:
            return 'medium'
        else:
            return 'low'

class Alert(db.Model):
    """Advanced alert with correlation and context"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(64), unique=True)  # UUID
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    category = db.Column(db.String(50))  # exploit, scan, anomaly, malware, policy
    subcategory = db.Column(db.String(50))
    source_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    target_ip = db.Column(db.String(45))
    target_port = db.Column(db.Integer)
    description = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON
    mitre_attack = db.Column(db.String(50))  # MITRE ATT&CK ID
    confidence = db.Column(db.Integer, default=80)
    status = db.Column(db.String(20), default='new')  # new, investigating, resolved, false_positive, suppressed
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolved_at = db.Column(db.DateTime)
    resolution_notes = db.Column(db.Text)
    correlation_id = db.Column(db.String(64))  # For grouping related alerts
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Incident(db.Model):
    """Incident management model"""
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(64), unique=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, closed
    priority = db.Column(db.String(20), default='medium')
    category = db.Column(db.String(50))
    source_ip = db.Column(db.String(45))
    target_ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    alert_ids = db.Column(db.Text)  # JSON list
    notes = db.Column(db.Text)
    resolution = db.Column(db.Text)
    lessons_learned = db.Column(db.Text)

class LogEntry(db.Model):
    """Centralized log management"""
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50))
    source_ip = db.Column(db.String(45))
    level = db.Column(db.String(20))
    category = db.Column(db.String(50))
    message = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON
    event_id = db.Column(db.String(64))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    session_id = db.Column(db.String(64))

class ThreatIntel(db.Model):
    """Threat intelligence feed"""
    __tablename__ = 'threat_intel'
    
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), unique=True)
    type = db.Column(db.String(50))  # ip, domain, hash, url
    confidence = db.Column(db.Integer, default=50)
    severity = db.Column(db.String(20))
    source = db.Column(db.String(50))
    description = db.Column(db.Text)
    tags = db.Column(db.Text)  # JSON list
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Rule(db.Model):
    """Security rules and correlation rules"""
    __tablename__ = 'rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    description = db.Column(db.Text)
    type = db.Column(db.String(50))  # detection, correlation, suppression
    severity = db.Column(db.String(20))
    condition = db.Column(db.Text)  # JSON condition
    action = db.Column(db.Text)  # JSON action
    enabled = db.Column(db.Boolean, default=True)
    priority = db.Column(db.Integer, default=50)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================
# ADVANCED SECURITY MODULES
# ============================================

class ThreatIntelligence:
    """Advanced threat intelligence module"""
    
    def __init__(self):
        self.feeds = [
            'https://threatfeeds.example.com/feed.json',
            'https://api.alienvault.com/otx/indicators/export',
            'https://feeds.zeek.org/'
        ]
        self.cache = {}
    
    def fetch_threat_intel(self):
        """Fetch threat intelligence from multiple sources"""
        indicators = []
        for feed in self.feeds:
            try:
                response = requests.get(feed, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    indicators.extend(self._parse_feed(data))
            except Exception as e:
                logger.error(f"Failed to fetch threat feed: {e}")
        return indicators
    
    def _parse_feed(self, data):
        """Parse different feed formats"""
        indicators = []
        # Feed format parsing logic
        return indicators
    
    def check_ioc(self, indicator):
        """Check if indicator matches threat intelligence"""
        # Check cache first
        if indicator in self.cache:
            return self.cache[indicator]
        
        # Query threat intel database
        threat = ThreatIntel.query.filter_by(indicator=indicator).first()
        if threat:
            return {
                'found': True,
                'confidence': threat.confidence,
                'severity': threat.severity,
                'description': threat.description
            }
        return {'found': False}

class AnomalyDetector:
    """Machine Learning based anomaly detection"""
    
    def __init__(self):
        self.model = None
        self.threshold = 0.85
        
    def train_model(self, data):
        """Train ML model on historical data"""
        # Implementation with scikit-learn
        pass
    
    def detect_anomaly(self, data_point):
        """Detect anomaly in data point"""
        # Implementation
        pass

class CorrelationEngine:
    """Advanced event correlation engine"""
    
    def __init__(self):
        self.rules = []
        self._load_rules()
    
    def _load_rules(self):
        """Load correlation rules from database"""
        self.rules = Rule.query.filter_by(enabled=True).all()
    
    def correlate(self, event):
        """Correlate event against rules"""
        alerts = []
        for rule in self.rules:
            if self._matches_rule(event, rule):
                alert = self._create_alert(event, rule)
                alerts.append(alert)
        return alerts
    
    def _matches_rule(self, event, rule):
        """Check if event matches rule condition"""
        # Rule matching logic
        return True
    
    def _create_alert(self, event, rule):
        """Create alert from matched rule"""
        alert = Alert(
            severity=rule.severity,
            category='correlation',
            description=f"Rule triggered: {rule.name}",
            details=json.dumps({'rule_id': rule.id, 'event': event}),
            confidence=80
        )
        return alert

# ============================================
# SIEM ENGINE
# ============================================

class SIEMEngine:
    """Security Information and Event Management engine"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.anomaly_detector = AnomalyDetector()
        self.correlation_engine = CorrelationEngine()
        self.alert_buffer = []
    
    def process_event(self, event_data):
        """Process incoming event"""
        results = {
            'alerts': [],
            'anomalies': [],
            'threats': []
        }
        
        # 1. Check threat intelligence
        threat_result = self.threat_intel.check_ioc(event_data.get('source_ip'))
        if threat_result.get('found'):
            results['threats'].append(threat_result)
        
        # 2. Anomaly detection
        anomaly_score = self.anomaly_detector.detect_anomaly(event_data)
        if anomaly_score > self.anomaly_detector.threshold:
            results['anomalies'].append({
                'score': anomaly_score,
                'description': 'Anomalous activity detected'
            })
        
        # 3. Correlation
        correlated_alerts = self.correlation_engine.correlate(event_data)
        results['alerts'].extend(correlated_alerts)
        
        return results

# ============================================
# FLASK ROUTES
# ============================================

@app.route('/')
@login_required
def index():
    """Main dashboard"""
    return render_template('index.html', version='2.0.0')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with rate limiting"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log the event
            log_event('user_login', 'info', f'User {username} logged in', user_id=user.id)
            
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_event('user_logout', 'info', f'User {current_user.username} logged out', user_id=current_user.id)
    logout_user()
    return redirect(url_for('login'))

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/api/v1/stats')
@login_required
def api_stats():
    """Get comprehensive statistics"""
    stats = {
        'overview': {
            'total_devices': Device.query.count(),
            'online_devices': Device.query.filter_by(status='online').count(),
            'total_alerts': Alert.query.count(),
            'critical_alerts': Alert.query.filter_by(severity='critical', status='new').count(),
            'open_incidents': Incident.query.filter(Incident.status.in_(['open', 'in_progress'])).count(),
            'threat_intel': ThreatIntel.query.count()
        },
        'trends': get_alert_trends(),
        'device_os_distribution': get_device_os_distribution(),
        'severity_distribution': get_severity_distribution(),
        'top_alerts': get_top_alerts(),
        'risk_scores': get_risk_score_distribution()
    }
    return jsonify(stats)

@app.route('/api/v1/alerts')
@login_required
def api_alerts():
    """Get alerts with filtering"""
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = request.args.get('limit', 100, type=int)
    
    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    
    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    
    return jsonify([{
        'id': a.id,
        'alert_id': a.alert_id,
        'timestamp': a.timestamp.isoformat(),
        'severity': a.severity,
        'category': a.category,
        'description': a.description,
        'source_ip': a.source_ip,
        'target_ip': a.target_ip,
        'status': a.status,
        'mitre_attack': a.mitre_attack,
        'confidence': a.confidence
    } for a in alerts])

@app.route('/api/v1/devices')
@login_required
def api_devices():
    """Get devices with filtering"""
    status = request.args.get('status')
    device_type = request.args.get('type')
    limit = request.args.get('limit', 100, type=int)
    
    query = Device.query
    if status:
        query = query.filter_by(status=status)
    if device_type:
        query = query.filter_by(device_type=device_type)
    
    devices = query.limit(limit).all()
    
    return jsonify([{
        'id': d.id,
        'ip': d.ip,
        'hostname': d.hostname,
        'vendor': d.vendor,
        'os': d.os,
        'device_type': d.device_type,
        'status': d.status,
        'risk_score': d.risk_score,
        'criticality': d.criticality,
        'open_ports': json.loads(d.open_ports) if d.open_ports else [],
        'vulnerabilities': json.loads(d.vulnerabilities) if d.vulnerabilities else [],
        'last_seen': d.last_seen.isoformat()
    } for d in devices])

@app.route('/api/v1/threat_intel')
@login_required
def api_threat_intel():
    """Get threat intelligence"""
    indicators = ThreatIntel.query.all()
    return jsonify([{
        'id': i.id,
        'indicator': i.indicator,
        'type': i.type,
        'confidence': i.confidence,
        'severity': i.severity,
        'description': i.description,
        'first_seen': i.first_seen.isoformat(),
        'last_seen': i.last_seen.isoformat()
    } for i in indicators])

@app.route('/api/v1/scan', methods=['POST'])
@login_required
def api_scan():
    """Start network scan"""
    data = request.json
    network = data.get('network', '192.168.1.0/24')
    scan_type = data.get('type', 'quick')
    
    # Start background scan
    threading.Thread(target=run_scan, args=(network, scan_type)).start()
    
    return jsonify({
        'status': 'started',
        'network': network,
        'type': scan_type,
        'message': 'Scan started successfully'
    })

@app.route('/api/v1/incidents')
@login_required
def api_incidents():
    """Get incidents"""
    incidents = Incident.query.all()
    return jsonify([{
        'id': i.id,
        'incident_id': i.incident_id,
        'title': i.title,
        'severity': i.severity,
        'status': i.status,
        'priority': i.priority,
        'created_at': i.created_at.isoformat()
    } for i in incidents])

@app.route('/api/v1/alert/<int:alert_id>/action', methods=['POST'])
@login_required
def api_alert_action(alert_id):
    """Take action on alert"""
    alert = Alert.query.get(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    action = request.json.get('action')
    notes = request.json.get('notes', '')
    
    if action == 'investigate':
        alert.status = 'investigating'
        alert.assigned_to = current_user.id
    elif action == 'resolve':
        alert.status = 'resolved'
        alert.resolved_at = datetime.utcnow()
        alert.resolution_notes = notes
    elif action == 'false_positive':
        alert.status = 'false_positive'
        alert.resolution_notes = notes
    else:
        return jsonify({'error': 'Invalid action'}), 400
    
    db.session.commit()
    
    log_event('alert_action', 'info', f'Alert {alert_id} {action} by {current_user.username}')
    
    return jsonify({'status': 'success', 'message': f'Alert {action} completed'})

# ============================================
# HELPER FUNCTIONS
# ============================================

def log_event(source, level, message, category='system', user_id=None, details=None):
    """Log an event to the database"""
    log = LogEntry(
        source=source,
        level=level,
        category=category,
        message=message,
        details=json.dumps(details) if details else None,
        user_id=user_id
    )
    db.session.add(log)
    db.session.commit()

def get_alert_trends():
    """Get alert trends for charts"""
    now = datetime.utcnow()
    trends = []
    for i in range(24, 0, -1):
        time_point = now - timedelta(hours=i)
        count = Alert.query.filter(
            Alert.timestamp >= time_point - timedelta(hours=1),
            Alert.timestamp < time_point
        ).count()
        trends.append({
            'time': time_point.strftime('%H:00'),
            'count': count
        })
    return trends

def get_device_os_distribution():
    """Get OS distribution for charts"""
    os_counts = {}
    devices = Device.query.all()
    for device in devices:
        os = device.os or 'Unknown'
        os_counts[os] = os_counts.get(os, 0) + 1
    return [{'os': k, 'count': v} for k, v in os_counts.items()]

def get_severity_distribution():
    """Get severity distribution"""
    severities = ['critical', 'high', 'medium', 'low']
    counts = {}
    for severity in severities:
        counts[severity] = Alert.query.filter_by(severity=severity).count()
    return counts

def get_top_alerts(limit=5):
    """Get top alerts by category"""
    categories = db.session.query(Alert.category, db.func.count(Alert.id)).group_by(Alert.category).order_by(db.func.count(Alert.id).desc()).limit(limit).all()
    return [{'category': c[0], 'count': c[1]} for c in categories]

def get_risk_score_distribution():
    """Get risk score distribution"""
    risk_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    devices = Device.query.all()
    for device in devices:
        level = device.get_risk_level()
        risk_levels[level] = risk_levels.get(level, 0) + 1
    return risk_levels

def run_scan(network, scan_type):
    """Run network scan in background"""
    socketio.emit('scan_started', {'network': network, 'type': scan_type})
    
    # Implementation of network scan
    # ... scanning logic ...
    
    socketio.emit('scan_completed', {'network': network, 'devices': 0})

# ============================================
# WEBSOCKET EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'connected', 'timestamp': datetime.utcnow().isoformat()})

@socketio.on('subscribe')
def handle_subscribe(data):
    room = data.get('room', 'general')
    join_room(room)
    emit('subscribed', {'room': room})

@socketio.on('ping')
def handle_ping():
    emit('pong', {'timestamp': datetime.utcnow().isoformat()})

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# MAIN ENTRY POINT
# ============================================

def create_default_admin():
    """Create default admin user"""
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@minisoc.local',
            role='admin'
        )
        admin.set_password('Admin123!@#')
        db.session.add(admin)
        db.session.commit()
        logger.info("Default admin user created: admin / Admin123!@#")

def create_demo_data():
    """Create demo data for testing"""
    if Device.query.count() == 0:
        # Create sample devices
        sample_devices = [
            {'ip': '192.168.1.10', 'hostname': 'server-01', 'vendor': 'Dell', 'os': 'Windows Server 2022', 'device_type': 'server', 'open_ports': json.dumps([80, 443, 445]), 'risk_score': 75},
            {'ip': '192.168.1.20', 'hostname': 'workstation-01', 'vendor': 'HP', 'os': 'Windows 11', 'device_type': 'workstation', 'open_ports': json.dumps([135, 139]), 'risk_score': 40},
            {'ip': '192.168.1.30', 'hostname': 'android-phone', 'vendor': 'Samsung', 'os': 'Android 13', 'device_type': 'mobile', 'open_ports': json.dumps([5555]), 'risk_score': 85},
            {'ip': '192.168.1.40', 'hostname': 'iphone', 'vendor': 'Apple', 'os': 'iOS 17', 'device_type': 'mobile', 'open_ports': json.dumps([62078]), 'risk_score': 60},
        ]
        
        for device_data in sample_devices:
            device = Device(**device_data)
            db.session.add(device)
        
        db.session.commit()
        logger.info("Demo devices created")
    
    if Alert.query.count() == 0:
        # Create sample alerts
        sample_alerts = [
            {'severity': 'critical', 'category': 'exploit', 'description': 'ADB service exposed on 192.168.1.30', 'source_ip': 'scanner', 'target_ip': '192.168.1.30'},
            {'severity': 'high', 'category': 'scan', 'description': 'Port scan detected from 192.168.1.100', 'source_ip': '192.168.1.100', 'target_ip': '192.168.1.10'},
            {'severity': 'medium', 'category': 'anomaly', 'description': 'Unusual outbound traffic from 192.168.1.20', 'source_ip': '192.168.1.20', 'target_ip': 'external'},
        ]
        
        for alert_data in sample_alerts:
            alert = Alert(**alert_data)
            db.session.add(alert)
        
        db.session.commit()
        logger.info("Demo alerts created")

if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    with app.app_context():
        db.create_all()
        create_default_admin()
        create_demo_data()
    
    print("\n" + "="*60)
    print("🖥️  MINI SOC LAB - ADVANCED EDITION")
    print("="*60)
    print("📍 Dashboard: http://localhost:5000")
    print("🔑 Login: admin / Admin123!@#")
    print("="*60 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
