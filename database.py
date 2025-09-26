#!/usr/bin/env python3
"""
Database models and utilities for MELCloud integration
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
from datetime import datetime
import json
import sqlite3
import os
import shutil
import logging
import secrets
from typing import Optional

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore

db = SQLAlchemy()

_fernet_cached: Optional["Fernet"] = None
_key_path_cached: Optional[str] = None

def _default_key_path() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, 'instance', 'encryption.key')

def _get_fernet() -> Optional["Fernet"]:
    global _fernet_cached
    if _fernet_cached is not None:
        return _fernet_cached
    if Fernet is None:
        return None

    # 1) Prefer explicit env var
    env_key = os.environ.get("ENCRYPTION_KEY")
    if env_key:
        try:
            f = Fernet(env_key.encode("utf-8") if isinstance(env_key, str) else env_key)
            _fernet_cached = f
            return f
        except Exception as e:
            logging.warning(f"Invalid ENCRYPTION_KEY: {e}")

    # 2) Try key file (env override or default under instance/)
    key_file = os.environ.get("ENCRYPTION_KEY_FILE") or _default_key_path()
    # Cache path for transparency/debug
    global _key_path_cached
    _key_path_cached = key_file

    try:
        if os.path.exists(key_file):
            with open(key_file, 'rb') as fh:
                file_key = fh.read().strip()
            f = Fernet(file_key)
            _fernet_cached = f
            return f
    except Exception as e:
        logging.warning(f"Failed reading encryption key file '{key_file}': {e}")

    # 3) Generate and persist a new key
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        new_key = Fernet.generate_key()
        with open(key_file, 'wb') as fh:
            fh.write(new_key)
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            # Best effort on non-POSIX systems
            pass
        f = Fernet(new_key)
        logging.info(f"Generated new encryption key at '{key_file}'")
        _fernet_cached = f
        return f
    except Exception as e:
        logging.warning(f"Could not generate/persist encryption key: {e}")
        return None

def get_encryption_status() -> dict:
    """Return current encryption status without exposing secrets.

    Fields:
    - enabled: bool — True if a working Fernet instance is available
    - source: str — 'env' if ENCRYPTION_KEY used, else 'file' if a key file is used, else 'none'
    - key_file_path: str|None — path to the key file if used (not the key itself)
    - key_file_present: bool — whether the key file exists
    """
    status = {
        'enabled': False,
        'source': 'none',
        'key_file_path': None,
        'key_file_present': False,
    }
    # Probe fernet
    f = _get_fernet()
    status['enabled'] = f is not None

    if os.environ.get('ENCRYPTION_KEY'):
        status['source'] = 'env'
        return status

    key_file = os.environ.get('ENCRYPTION_KEY_FILE') or _default_key_path()
    status['source'] = 'file'
    status['key_file_path'] = key_file
    status['key_file_present'] = os.path.exists(key_file)
    return status

def encrypt_password(plaintext: str) -> Optional[str]:
    f = _get_fernet()
    if not f or plaintext is None:
        return None
    try:
        return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception:
        return None

def decrypt_password(ciphertext: Optional[str]) -> Optional[str]:
    f = _get_fernet()
    if not f or not ciphertext:
        return None
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None
    except Exception:
        return None

def parse_datetime(datetime_str):
    """Parse datetime string to datetime object, handling various formats"""
    if not datetime_str:
        return None
    try:
        # Handle ISO format strings from MELCloud API
        if isinstance(datetime_str, str):
            # Try common MELCloud datetime formats
            formats = [
                '%Y-%m-%dT%H:%M:%S',      # 2025-08-28T21:28:00
                '%Y-%m-%dT%H:%M:%SZ',     # 2025-08-28T21:28:00Z
                '%Y-%m-%dT%H:%M:%S.%f',   # 2025-08-28T21:28:00.123456
                '%Y-%m-%dT%H:%M:%S.%fZ',  # 2025-08-28T21:28:00.123456Z
                '%Y-%m-%d %H:%M:%S',      # 2025-08-28 21:28:00
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(datetime_str, fmt)
                except ValueError:
                    continue
            
            # If none of the formats work, return None
            return None
        elif isinstance(datetime_str, datetime):
            return datetime_str
        else:
            return None
    except (ValueError, TypeError):
        return None

class User(db.Model):
    """User table to store MELCloud credentials"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=True)  # User's display name from MELCloud
    password_hash = db.Column(db.String(255), nullable=False)
    password_plain = db.Column(db.String(255), nullable=False)  # Legacy: plain password for API calls
    password_encrypted = db.Column(db.Text, nullable=True)  # Encrypted MELCloud password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to device data
    device_data = db.relationship('DeviceData', backref='user', lazy=True)
    
    def set_password(self, password):
        """Hash and set the password"""
        self.password_hash = generate_password_hash(password)
        # Encrypt if key is configured; avoid storing plaintext when possible
        enc = encrypt_password(password)
        self.password_encrypted = enc
        # If encryption worked, blank out legacy plaintext field; else keep legacy for compatibility
        self.password_plain = '' if enc else password
    
    def check_password(self, password):
        """Check if provided password matches the hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user to dictionary (excluding password)"""
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'updated_at': self.updated_at.isoformat() + 'Z' if self.updated_at else None
        }

def get_decrypted_melcloud_password(user: User) -> Optional[str]:
    """Return decrypted MELCloud password, falling back to legacy plaintext."""
    if getattr(user, 'password_encrypted', None):
        pwd = decrypt_password(user.password_encrypted)
        if pwd:
            return pwd
    if getattr(user, 'password_plain', None):
        return user.password_plain
    return None

class WebUser(UserMixin, db.Model):
    """Web application users table for website authentication"""
    __tablename__ = 'web_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Relationship to sessions
    sessions = db.relationship('WebSession', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set the password using bcrypt"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches the hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    def is_locked(self):
        """Check if account is temporarily locked"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            # Lock account for 30 minutes after 5 failed attempts
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
    
    def reset_failed_login(self):
        """Reset failed login attempts after successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
    
    def to_dict(self):
        """Convert user to dictionary (excluding password)"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() + 'Z' if self.created_at else None,
            'last_login': self.last_login.isoformat() + 'Z' if self.last_login else None
        }

class WebSession(db.Model):
    """Web session tracking for security"""
    __tablename__ = 'web_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('web_users.id'), nullable=False)
    ip_address = db.Column(db.String(45))  # Supports IPv6
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    def is_expired(self):
        """Check if session is expired"""
        return self.expires_at and self.expires_at < datetime.utcnow()
    
    def extend_session(self, hours=24):
        """Extend session expiration"""
        from datetime import timedelta
        self.expires_at = datetime.utcnow() + timedelta(hours=hours)
        self.last_activity = datetime.utcnow()

class DeviceData(db.Model):
    """Table to store MELCloud device data readings"""
    __tablename__ = 'device_data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Device identification
    device_id = db.Column(db.Integer, nullable=False)
    device_name = db.Column(db.String(255), nullable=False)
    device_type = db.Column(db.Integer)
    model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    online = db.Column(db.Boolean, default=True)
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_communication = db.Column(db.String(100))
    
    # Temperature readings (in Celsius)
    room_temperature = db.Column(db.Float)
    room_temperature_zone2 = db.Column(db.Float)
    set_temperature = db.Column(db.Float)
    outdoor_temperature = db.Column(db.Float)
    flow_temperature = db.Column(db.Float)
    return_temperature = db.Column(db.Float)
    tank_temperature = db.Column(db.Float)
    set_tank_temperature = db.Column(db.Float)
    
    # Energy data (in kWh)
    daily_heating_energy_consumed = db.Column(db.Float)
    daily_cooling_energy_consumed = db.Column(db.Float)
    daily_hot_water_energy_consumed = db.Column(db.Float)
    daily_heating_energy_produced = db.Column(db.Float)
    daily_cooling_energy_produced = db.Column(db.Float)
    daily_hot_water_energy_produced = db.Column(db.Float)
    daily_energy_date = db.Column(db.String(50))
    
    # COP calculation
    daily_cop = db.Column(db.Float)
    
    # System status
    power = db.Column(db.Boolean)
    operation_mode = db.Column(db.Integer)
    eco_hot_water = db.Column(db.Boolean)
    forced_hot_water = db.Column(db.Boolean)
    holiday_mode = db.Column(db.Boolean)
    unit_status = db.Column(db.Integer)
    defrost_mode = db.Column(db.Integer)
    last_legionella_activation_time = db.Column(db.DateTime)
    
    # WiFi/Network status
    wifi_signal = db.Column(db.Integer)
    wifi_adapter_status = db.Column(db.String(50))
    
    # Location info (JSON stored as text)
    location_info = db.Column(db.Text)  # Store structure info as JSON
    
    def calculate_cop(self):
        """Calculate and set the daily COP"""
        total_consumed = (
            (self.daily_heating_energy_consumed or 0) +
            (self.daily_cooling_energy_consumed or 0) +
            (self.daily_hot_water_energy_consumed or 0)
        )
        total_produced = (
            (self.daily_heating_energy_produced or 0) +
            (self.daily_cooling_energy_produced or 0) +
            (self.daily_hot_water_energy_produced or 0)
        )
        
        if total_consumed > 0:
            self.daily_cop = round(total_produced / total_consumed, 2)
        else:
            self.daily_cop = None
    
    def to_dict(self):
        """Convert device data to dictionary"""
        # Parse location info if it exists
        location = None
        if self.location_info:
            try:
                location = json.loads(self.location_info)
            except (json.JSONDecodeError, TypeError):
                location = None
        
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device_name,
            'device_type': self.device_type,
            'model': self.model,
            'serial_number': self.serial_number,
            'online': self.online,
            'timestamp': self.timestamp.isoformat() + 'Z' if self.timestamp else None,
            'last_communication': self.last_communication,
            
            # Temperature readings
            'room_temperature': self.room_temperature,
            'room_temperature_zone2': self.room_temperature_zone2,
            'set_temperature': self.set_temperature,
            'outdoor_temperature': self.outdoor_temperature,
            'flow_temperature': self.flow_temperature,
            'return_temperature': self.return_temperature,
            'tank_temperature': self.tank_temperature,
            'set_tank_temperature': self.set_tank_temperature,
            
            # Energy data
            'daily_heating_energy_consumed': self.daily_heating_energy_consumed,
            'daily_cooling_energy_consumed': self.daily_cooling_energy_consumed,
            'daily_hot_water_energy_consumed': self.daily_hot_water_energy_consumed,
            'daily_heating_energy_produced': self.daily_heating_energy_produced,
            'daily_cooling_energy_produced': self.daily_cooling_energy_produced,
            'daily_hot_water_energy_produced': self.daily_hot_water_energy_produced,
            'daily_energy_date': self.daily_energy_date,
            'daily_cop': self.daily_cop,
            
            # System status
            'power': self.power,
            'operation_mode': self.operation_mode,
            'eco_hot_water': self.eco_hot_water,
            'forced_hot_water': self.forced_hot_water,
            'holiday_mode': self.holiday_mode,
            'unit_status': self.unit_status,
            'defrost_mode': self.defrost_mode,
            
            # Network status
            'wifi_signal': self.wifi_signal,
            'wifi_adapter_status': self.wifi_adapter_status,
            
            # Location
            'location_info': location
        }


class APISettings(db.Model):
    """Table to store API configuration settings"""
    __tablename__ = 'api_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # API fetch interval in minutes (minimum 5, default 10)
    fetch_interval_minutes = db.Column(db.Integer, default=10, nullable=False)
    
    # Enable/disable API communications
    api_enabled = db.Column(db.Boolean, default=True, nullable=False)
    
    # Timestamp for when settings were last updated
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_by_user_id = db.Column(db.Integer, db.ForeignKey('web_users.id'))
    
    def to_dict(self):
        """Convert settings to dictionary"""
        return {
            'id': self.id,
            'fetch_interval_minutes': self.fetch_interval_minutes,
            'api_enabled': self.api_enabled,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by_user_id': self.updated_by_user_id
        }


class DeviceSchedule(db.Model):
    """Table to store device schedules"""
    __tablename__ = 'device_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    device_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('web_users.id'), nullable=False)
    schedule_type = db.Column(db.String(20), nullable=False)  # 'temperature', 'hot_water', 'holiday'
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    priority = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    rules = db.relationship('ScheduleRule', backref='schedule', lazy='dynamic', cascade='all, delete-orphan')
    execution_logs = db.relationship('ScheduleExecutionLog', backref='schedule', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert schedule to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'device_id': self.device_id,
            'user_id': self.user_id,
            'schedule_type': self.schedule_type,
            'is_active': self.is_active,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'rules': [rule.to_dict() for rule in self.rules]
        }


class ScheduleRule(db.Model):
    """Table to store individual schedule rules"""
    __tablename__ = 'schedule_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('device_schedules.id'), nullable=False)
    day_of_week = db.Column(db.Integer, nullable=True)  # 0=Monday, 6=Sunday, NULL=all days
    time_of_day = db.Column(db.Time, nullable=False)
    target_value = db.Column(db.Float, nullable=True)  # temperature or mode value
    conditions_json = db.Column(db.Text, nullable=True)  # JSON for conditional logic
    
    def to_dict(self):
        """Convert rule to dictionary"""
        return {
            'id': self.id,
            'schedule_id': self.schedule_id,
            'day_of_week': self.day_of_week,
            'time_of_day': self.time_of_day.strftime('%H:%M:%S') if self.time_of_day else None,
            'target_value': self.target_value,
            'conditions_json': self.conditions_json
        }


class ScheduleExecutionLog(db.Model):
    """Table to store schedule execution history"""
    __tablename__ = 'schedule_execution_log'
    
    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('device_schedules.id'), nullable=False)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    device_response_json = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        """Convert execution log to dictionary"""
        return {
            'id': self.id,
            'schedule_id': self.schedule_id,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'success': self.success,
            'error_message': self.error_message,
            'device_response_json': self.device_response_json
        }


class DeviceConfig(db.Model):
    """Table to store device configuration including timezone"""
    __tablename__ = 'device_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, nullable=False, unique=True)
    timezone = db.Column(db.String(50), nullable=False, default='UTC')
    device_name = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def to_dict(self):
        """Convert device config to dictionary"""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'timezone': self.timezone,
            'device_name': self.device_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


def init_database(app):
    """Initialize the database with the Flask app"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default schedules if they don't exist
        create_default_schedules()
        
        print("Database initialized successfully")

def create_default_schedules():
    """Create default system-wide schedules for each schedule type if they don't exist"""
    
    device_id = 1  # Default device ID - will be set properly when device data is available
    
    # Define default schedules (system-wide, not user-specific)
    default_schedules = [
        {
            'name': 'Heating Schedule',
            'schedule_type': 'temperature',
            'device_id': device_id,
            'user_id': 1,  # Use first admin user as owner for database constraints
            'priority': 1,
            'is_active': True
        },
        {
            'name': 'Hot Water Schedule', 
            'schedule_type': 'hot_water',
            'device_id': device_id,
            'user_id': 1,  # Use first admin user as owner for database constraints
            'priority': 2,
            'is_active': True
        },
        {
            'name': 'Holiday Mode Schedule',
            'schedule_type': 'holiday',
            'device_id': device_id,
            'user_id': 1,  # Use first admin user as owner for database constraints
            'priority': 3,
            'is_active': False  # Disabled by default
        }
    ]
    
    # Create schedules if they don't exist (check by schedule_type only, not user)
    for schedule_data in default_schedules:
        existing = DeviceSchedule.query.filter_by(
            schedule_type=schedule_data['schedule_type']
        ).first()
        
        if not existing:
            schedule = DeviceSchedule(
                name=schedule_data['name'],
                schedule_type=schedule_data['schedule_type'],
                device_id=schedule_data['device_id'],
                user_id=schedule_data['user_id'],
                priority=schedule_data['priority'],
                is_active=schedule_data['is_active']
            )
            db.session.add(schedule)
            print(f"Created default schedule: {schedule_data['name']}")
    
    try:
        db.session.commit()
        print("Default schedules created successfully")
    except Exception as e:
        print(f"Error creating default schedules: {e}")
        db.session.rollback()

def get_user():
    """Get the first (and only) user from the database"""
    return User.query.first()

def create_user(email, password):
    """Create a new user with email and password"""
    user = User(email=email)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return user

def update_user_credentials(user_id, email=None, password=None):
    """Update user credentials"""
    user = User.query.get(user_id)
    if not user:
        return None
    
    if email:
        user.email = email
    if password:
        user.set_password(password)
    
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    return user

def store_device_data(user_id, device_data_dict):
    """Store device data from MELCloud API response"""
    # Extract data from the device dictionary
    current_data = device_data_dict.get('current_data', {})
    structure = device_data_dict.get('structure', {})
    
    # Create new device data record
    device_data = DeviceData(
        user_id=user_id,
        device_id=device_data_dict.get('device_id'),
        device_name=device_data_dict.get('device_name'),
        device_type=device_data_dict.get('device_type'),
        model=device_data_dict.get('model'),
        serial_number=device_data_dict.get('serial_number'),
        online=device_data_dict.get('online', True),
        last_communication=device_data_dict.get('last_communication'),
        
        # Temperature readings
        room_temperature=current_data.get('room_temperature'),
        room_temperature_zone2=current_data.get('room_temperature_zone2') if current_data.get('room_temperature_zone2') != -39.0 else None,
        set_temperature=current_data.get('set_temperature'),
        outdoor_temperature=current_data.get('outdoor_temperature'),
        flow_temperature=current_data.get('flow_temperature'),
        return_temperature=current_data.get('return_temperature'),
        tank_temperature=current_data.get('tank_temperature'),
        set_tank_temperature=current_data.get('set_tank_temperature'),
        
        # Energy data
        daily_heating_energy_consumed=current_data.get('daily_energy_consumed', {}).get('heating'),
        daily_cooling_energy_consumed=current_data.get('daily_energy_consumed', {}).get('cooling'),
        daily_hot_water_energy_consumed=current_data.get('daily_energy_consumed', {}).get('hot_water'),
        daily_heating_energy_produced=current_data.get('daily_energy_produced', {}).get('heating'),
        daily_cooling_energy_produced=current_data.get('daily_energy_produced', {}).get('cooling'),
        daily_hot_water_energy_produced=current_data.get('daily_energy_produced', {}).get('hot_water'),
        daily_energy_date=current_data.get('daily_energy_consumed_date'),
        
        # System status
        power=current_data.get('power'),
        operation_mode=current_data.get('operation_mode'),
        eco_hot_water=current_data.get('eco_hot_water'),
        forced_hot_water=current_data.get('forced_hot_water'),
        holiday_mode=current_data.get('holiday_mode'),
        unit_status=current_data.get('unit_status'),
        defrost_mode=current_data.get('defrost_mode'),
        last_legionella_activation_time=parse_datetime(current_data.get('last_legionella_activation_time')),
        
        # Network status
        wifi_signal=current_data.get('wifi_signal'),
        wifi_adapter_status=current_data.get('wifi_adapter_status'),
        
        # Location info as JSON
        location_info=json.dumps(structure) if structure else None
    )
    
    # Calculate COP
    device_data.calculate_cop()
    
    # Save to database
    db.session.add(device_data)
    db.session.commit()
    
    return device_data

def get_device_data_history(user_id, limit=100, offset=0, date_from=None, date_to=None):
    """Get historical device data for a user with optional date filtering"""
    query = DeviceData.query.filter_by(user_id=user_id)
    
    # Apply date filters if provided
    if date_from:
        try:
            from datetime import datetime
            # Try ISO format first (for hour-based filtering)
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                # Fall back to date-only format
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass  # Ignore invalid date format
    
    if date_to:
        try:
            from datetime import datetime, timedelta
            # Try ISO format first (for hour-based filtering)
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                # Fall back to date-only format and include the entire day
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass  # Ignore invalid date format
    
    # If date filtering is being used, order by timestamp ASC to get chronological data
    # Otherwise, keep DESC for getting latest data first
    if date_from or date_to:
        query = query.order_by(DeviceData.timestamp.asc())
    else:
        query = query.order_by(DeviceData.timestamp.desc())
    
    query = query.offset(offset).limit(limit)
    
    return query.all()

def get_device_data_history_count(user_id, date_from=None, date_to=None):
    """Get total count of historical device data for a user with optional date filtering"""
    query = DeviceData.query.filter_by(user_id=user_id)
    # Apply date filters if provided
    if date_from:
        try:
            from datetime import datetime
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass
    if date_to:
        try:
            from datetime import datetime, timedelta
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass
    return query.count()

def get_latest_device_data(user_id, device_id=None):
    """Get the latest device data entry for a user (optionally for specific device)"""
    query = DeviceData.query.filter_by(user_id=user_id)
    if device_id:
        query = query.filter_by(device_id=device_id)
    
    return query.order_by(DeviceData.timestamp.desc()).first()

def get_latest_devices_for_dashboard(user_id):
    """Get latest device data formatted for dashboard frontend"""
    # Fetch records ordered by newest first. We deduplicate per device id in Python to
    # avoid relying on exact timestamp equality (SQLite stores DateTime as TEXT).
    records = DeviceData.query.filter_by(user_id=user_id).order_by(DeviceData.timestamp.desc()).all()

    if not records:
        return []

    latest_by_device = {}
    for record in records:
        device_id = record.device_id
        if device_id not in latest_by_device:
            latest_by_device[device_id] = record

    # Convert to frontend format (MELCloud API structure)
    # Preserve deterministic ordering (newest first)
    sorted_devices = sorted(
        latest_by_device.values(),
        key=lambda d: d.timestamp or datetime.min,
        reverse=True
    )

    formatted_devices = []
    for device in sorted_devices:
        # Parse location info if it's JSON string
        location_info = {}
        if device.location_info:
            try:
                if isinstance(device.location_info, str):
                    location_info = json.loads(device.location_info)
                elif isinstance(device.location_info, dict):
                    location_info = device.location_info
            except (json.JSONDecodeError, TypeError):
                location_info = {}
        # Transform database flat structure to nested MELCloud format
        device_dict = {
            "device_id": device.device_id,
            "device_name": device.device_name,
            "device_type": device.device_type,
            "model": device.model,
            "serial_number": device.serial_number,
            "online": device.online,
            
            # Current data in expected nested format
            "current_data": {
                # Temperature readings
                "room_temperature": device.room_temperature,
                "room_temperature_zone2": device.room_temperature_zone2,
                "set_temperature": device.set_temperature,
                "outdoor_temperature": device.outdoor_temperature,
                "flow_temperature": device.flow_temperature,
                "return_temperature": device.return_temperature,
                "tank_temperature": device.tank_temperature,
                "set_tank_temperature": device.set_tank_temperature,
                
                # Energy data in nested format expected by frontend
                "daily_energy_consumed": {
                    "heating": device.daily_heating_energy_consumed or 0,
                    "cooling": device.daily_cooling_energy_consumed or 0,
                    "hot_water": device.daily_hot_water_energy_consumed or 0
                },
                "daily_energy_produced": {
                    "heating": device.daily_heating_energy_produced or 0,
                    "cooling": device.daily_cooling_energy_produced or 0,
                    "hot_water": device.daily_hot_water_energy_produced or 0
                },
                "daily_energy_date": device.daily_energy_date,
                "daily_cop": device.daily_cop,
                
                # System status
                "power": device.power,
                "operation_mode": device.operation_mode,
                "eco_hot_water": device.eco_hot_water,
                "forced_hot_water": device.forced_hot_water,
                "holiday_mode": device.holiday_mode,
                "unit_status": device.unit_status,
                "defrost_mode": device.defrost_mode,
                "last_legionella_activation_time": device.last_legionella_activation_time.isoformat() + 'Z' if device.last_legionella_activation_time else None,
                
                # Network status
                "wifi_signal": device.wifi_signal,
                "wifi_adapter_status": device.wifi_adapter_status
            },
            
            # Structure information (for location display)
            "structure": {
                "structure_name": location_info.get("structure_name", ""),
                "address_line1": location_info.get("address_line1", ""),
                "address_line2": location_info.get("address_line2", ""),
                "city": location_info.get("city", ""),
                "postcode": location_info.get("postcode", ""),
                "country": location_info.get("country", ""),
                "country_name": location_info.get("country_name", ""),
                "timezone": location_info.get("timezone", ""),
                "latitude": location_info.get("latitude"),
                "longitude": location_info.get("longitude"),
                "location_id": location_info.get("location_id"),
                "building_type": location_info.get("building_type"),
                "property_type": location_info.get("property_type"),
                "date_built": location_info.get("date_built")
            },
            
            # Timestamps
            "timestamp": device.timestamp.isoformat() + 'Z' if device.timestamp else None,
            "last_communication": device.last_communication
        }
        formatted_devices.append(device_dict)
    
    return formatted_devices

def get_daily_energy_summary(user_id, limit=100, offset=0, date_from=None, date_to=None):
    """Get daily energy summary with calculated COP values - simplified version"""
    # Use SQLAlchemy ORM instead of raw SQL for now to avoid issues
    query = DeviceData.query.filter_by(user_id=user_id).filter(DeviceData.daily_energy_date.isnot(None))
    
    # Apply date filters if provided
    if date_from:
        try:
            from datetime import datetime
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            from datetime import datetime, timedelta
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass
    
    # Get all records and group by daily_energy_date in Python for now
    records = query.order_by(DeviceData.daily_energy_date.desc(), DeviceData.timestamp.asc()).all()
    
    # Group by daily_energy_date
    daily_groups = {}
    for record in records:
        date_key = record.daily_energy_date
        if date_key not in daily_groups:
            daily_groups[date_key] = []
        daily_groups[date_key].append(record)
    
    # Process each day and select 3rd record (or fallback)
    daily_summaries = []
    for date_key, day_records in daily_groups.items():
        # Select record based on availability
        if len(day_records) >= 3:
            selected_record = day_records[2]  # 3rd record (0-indexed)
        elif len(day_records) >= 2:
            selected_record = day_records[1]  # 2nd record
        else:
            selected_record = day_records[0]  # 1st record
        
        # Extract energy values
        heating_consumed = selected_record.daily_heating_energy_consumed or 0
        cooling_consumed = selected_record.daily_cooling_energy_consumed or 0
        hot_water_consumed = selected_record.daily_hot_water_energy_consumed or 0
        heating_produced = selected_record.daily_heating_energy_produced or 0
        cooling_produced = selected_record.daily_cooling_energy_produced or 0
        hot_water_produced = selected_record.daily_hot_water_energy_produced or 0
        
        # Calculate COP values
        heating_cop = round(heating_produced / heating_consumed, 2) if heating_consumed > 0 else None
        hot_water_cop = round(hot_water_produced / hot_water_consumed, 2) if hot_water_consumed > 0 else None
        
        # Calculate totals
        total_consumed = heating_consumed + cooling_consumed + hot_water_consumed
        total_produced = heating_produced + cooling_produced + hot_water_produced
        total_cop = round(total_produced / total_consumed, 2) if total_consumed > 0 else None
        
        daily_summary = {
            'daily_energy_date': selected_record.daily_energy_date,
            'timestamp': selected_record.timestamp.isoformat() + 'Z' if selected_record.timestamp else None,
            'device_name': selected_record.device_name,
            
            # Consumed energy
            'heating_consumed': heating_consumed,
            'cooling_consumed': cooling_consumed,
            'hot_water_consumed': hot_water_consumed,
            'total_consumed': total_consumed,
            
            # Produced energy  
            'heating_produced': heating_produced,
            'cooling_produced': cooling_produced,
            'hot_water_produced': hot_water_produced,
            'total_produced': total_produced,
            
            # COP values
            'heating_cop': heating_cop,
            'hot_water_cop': hot_water_cop,
            'total_cop': total_cop
        }
        
        daily_summaries.append(daily_summary)
    
    # Sort by date descending and apply pagination
    daily_summaries.sort(key=lambda x: x['daily_energy_date'], reverse=True)
    return daily_summaries[offset:offset + limit]


def get_monthly_energy_summary(user_id, limit=24, offset=0, date_from=None, date_to=None):
    """Get monthly energy summary with aggregated values and calculated COP values"""
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    query = DeviceData.query.filter_by(user_id=user_id).filter(DeviceData.daily_energy_date.isnot(None))
    
    # Apply date filters if provided
    if date_from:
        try:
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass
    
    # Get all records
    records = query.order_by(DeviceData.daily_energy_date.desc(), DeviceData.timestamp.asc()).all()
    
    # Group by daily_energy_date first, then by month
    daily_groups = {}
    for record in records:
        date_key = record.daily_energy_date
        if date_key not in daily_groups:
            daily_groups[date_key] = []
        daily_groups[date_key].append(record)
    
    # Process each day to get daily values
    daily_summaries = []
    for date_key, day_records in daily_groups.items():
        # Select record based on availability (same logic as daily summary)
        if len(day_records) >= 3:
            selected_record = day_records[2]  # 3rd record
        elif len(day_records) >= 2:
            selected_record = day_records[1]  # 2nd record
        else:
            selected_record = day_records[0]  # 1st record
        
        daily_summaries.append({
            'date': date_key,
            'heating_consumed': selected_record.daily_heating_energy_consumed or 0,
            'cooling_consumed': selected_record.daily_cooling_energy_consumed or 0,
            'hot_water_consumed': selected_record.daily_hot_water_energy_consumed or 0,
            'heating_produced': selected_record.daily_heating_energy_produced or 0,
            'cooling_produced': selected_record.daily_cooling_energy_produced or 0,
            'hot_water_produced': selected_record.daily_hot_water_energy_produced or 0,
            'timestamp': selected_record.timestamp,
            'device_name': selected_record.device_name
        })
    
    # Group daily summaries by month
    monthly_groups = defaultdict(lambda: {
        'heating_consumed': 0,
        'cooling_consumed': 0, 
        'hot_water_consumed': 0,
        'heating_produced': 0,
        'cooling_produced': 0,
        'hot_water_produced': 0,
        'days_count': 0,
        'latest_timestamp': None,
        'device_name': None
    })
    
    for daily_summary in daily_summaries:
        try:
            # Parse the date string to get year-month
            if 'T' in daily_summary['date']:
                date_obj = datetime.fromisoformat(daily_summary['date'].replace('Z', '+00:00'))
            else:
                date_obj = datetime.strptime(daily_summary['date'], '%Y-%m-%d')
            
            month_key = date_obj.strftime('%Y-%m')  # e.g., "2024-08"
            
            # Accumulate monthly values
            monthly_groups[month_key]['heating_consumed'] += daily_summary['heating_consumed']
            monthly_groups[month_key]['cooling_consumed'] += daily_summary['cooling_consumed']
            monthly_groups[month_key]['hot_water_consumed'] += daily_summary['hot_water_consumed']
            monthly_groups[month_key]['heating_produced'] += daily_summary['heating_produced']
            monthly_groups[month_key]['cooling_produced'] += daily_summary['cooling_produced']
            monthly_groups[month_key]['hot_water_produced'] += daily_summary['hot_water_produced']
            monthly_groups[month_key]['days_count'] += 1
            
            # Keep track of latest timestamp and device name
            if (monthly_groups[month_key]['latest_timestamp'] is None or 
                daily_summary['timestamp'] > monthly_groups[month_key]['latest_timestamp']):
                monthly_groups[month_key]['latest_timestamp'] = daily_summary['timestamp']
                monthly_groups[month_key]['device_name'] = daily_summary['device_name']
                
        except (ValueError, TypeError):
            continue
    
    # Convert to list and calculate COP values
    monthly_summaries = []
    for month_key, month_data in sorted(monthly_groups.items(), reverse=True):
        heating_consumed = round(month_data['heating_consumed'], 2)
        cooling_consumed = round(month_data['cooling_consumed'], 2)
        hot_water_consumed = round(month_data['hot_water_consumed'], 2)
        heating_produced = round(month_data['heating_produced'], 2)
        cooling_produced = round(month_data['cooling_produced'], 2)
        hot_water_produced = round(month_data['hot_water_produced'], 2)
        
        # Calculate COP values
        heating_cop = round(heating_produced / heating_consumed, 2) if heating_consumed > 0 else None
        hot_water_cop = round(hot_water_produced / hot_water_consumed, 2) if hot_water_consumed > 0 else None
        
        # Calculate totals
        total_consumed = heating_consumed + cooling_consumed + hot_water_consumed
        total_produced = heating_produced + cooling_produced + hot_water_produced
        total_cop = round(total_produced / total_consumed, 2) if total_consumed > 0 else None
        
        monthly_summary = {
            'monthly_energy_date': month_key,  # e.g., "2024-08"
            'timestamp': month_data['latest_timestamp'].isoformat() + 'Z' if month_data['latest_timestamp'] else None,
            'device_name': month_data['device_name'],
            'days_in_month': month_data['days_count'],
            
            # Consumed energy
            'heating_consumed': heating_consumed,
            'cooling_consumed': cooling_consumed,
            'hot_water_consumed': hot_water_consumed,
            'total_consumed': total_consumed,
            
            # Produced energy
            'heating_produced': heating_produced,
            'cooling_produced': cooling_produced,
            'hot_water_produced': hot_water_produced,
            'total_produced': total_produced,
            
            # COP values
            'heating_cop': heating_cop,
            'hot_water_cop': hot_water_cop,
            'total_cop': total_cop
        }
        
        monthly_summaries.append(monthly_summary)
    
    # Apply limit and offset
    start_idx = offset
    end_idx = start_idx + limit if limit else len(monthly_summaries)
    
    return monthly_summaries[start_idx:end_idx]


def check_database_integrity():
    """Check database integrity and return health status"""
    try:
        # Get database path from current app config
        from flask import current_app
        db_uri = current_app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri[10:]  # Remove 'sqlite:///'
        else:
            return {'healthy': False, 'error': 'Not a SQLite database'}
        
        if not os.path.exists(db_path):
            return {'healthy': False, 'error': 'Database file does not exist'}
        
        # Check file permissions
        if not os.access(db_path, os.R_OK | os.W_OK):
            return {'healthy': False, 'error': 'Database file permissions issue'}
        
        # Check SQLite integrity
        conn = sqlite3.connect(db_path, timeout=10)
        cursor = conn.cursor()
        
        # Run integrity check
        cursor.execute('PRAGMA integrity_check')
        result = cursor.fetchone()
        
        if result[0] != 'ok':
            conn.close()
            return {'healthy': False, 'error': f'Integrity check failed: {result[0]}'}
        
        # Check if database is readonly
        cursor.execute('PRAGMA journal_mode')
        journal_mode = cursor.fetchone()[0]
        
        # Try a simple write operation to test if readonly
        cursor.execute('PRAGMA user_version')
        version = cursor.fetchone()[0]
        cursor.execute(f'PRAGMA user_version = {version}')
        
        conn.close()
        
        return {
            'healthy': True, 
            'journal_mode': journal_mode,
            'file_size': os.path.getsize(db_path),
            'writable': True
        }
        
    except sqlite3.OperationalError as e:
        error_msg = str(e)
        if 'readonly database' in error_msg.lower():
            return {'healthy': False, 'error': 'Database is readonly', 'readonly': True}
        elif 'locked' in error_msg.lower():
            return {'healthy': False, 'error': 'Database is locked', 'locked': True}
        else:
            return {'healthy': False, 'error': f'SQLite error: {error_msg}'}
    except Exception as e:
        return {'healthy': False, 'error': f'Database check failed: {str(e)}'}


def recover_database():
    """Attempt to recover from database issues"""
    try:
        from flask import current_app
        db_uri = current_app.config['SQLALCHEMY_DATABASE_URI']
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri[10:]
        else:
            return {'success': False, 'error': 'Not a SQLite database'}
        
        logging.info("Database recovery: Starting recovery process")
        
        # Step 1: Check if database file exists
        if not os.path.exists(db_path):
            logging.warning("Database recovery: Database file missing, will recreate")
            # Ensure instance directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            # Recreate database
            db.create_all()
            return {'success': True, 'action': 'recreated_database'}
        
        # Step 2: Backup current database
        backup_path = f"{db_path}.backup.{int(datetime.now().timestamp())}"
        shutil.copy2(db_path, backup_path)
        logging.info(f"Database recovery: Created backup at {backup_path}")
        
        # Step 3: Remove WAL and journal files if they exist
        wal_files = [f"{db_path}-wal", f"{db_path}-shm", f"{db_path}-journal"]
        removed_files = []
        for wal_file in wal_files:
            if os.path.exists(wal_file):
                try:
                    os.remove(wal_file)
                    removed_files.append(wal_file)
                    logging.info(f"Database recovery: Removed {wal_file}")
                except Exception as e:
                    logging.warning(f"Database recovery: Failed to remove {wal_file}: {str(e)}")
        
        # Step 4: Try to fix permissions
        try:
            os.chmod(db_path, 0o666)
            logging.info("Database recovery: Updated file permissions")
        except Exception as e:
            logging.warning(f"Database recovery: Failed to update permissions: {str(e)}")
        
        # Step 5: Test database after cleanup
        integrity_check = check_database_integrity()
        if integrity_check['healthy']:
            return {
                'success': True, 
                'action': 'cleaned_up_locks',
                'removed_files': removed_files,
                'backup_path': backup_path
            }
        
        # Step 6: If still not healthy and marked as readonly, try to recreate
        if integrity_check.get('readonly') or integrity_check.get('locked'):
            logging.warning("Database recovery: Database still readonly/locked, attempting recreate")
            try:
                # Move old database aside
                corrupted_path = f"{db_path}.corrupted.{int(datetime.now().timestamp())}"
                os.rename(db_path, corrupted_path)
                
                # Recreate database
                db.create_all()
                
                return {
                    'success': True, 
                    'action': 'recreated_database',
                    'corrupted_path': corrupted_path,
                    'backup_path': backup_path
                }
            except Exception as e:
                logging.error(f"Database recovery: Failed to recreate database: {str(e)}")
                return {'success': False, 'error': f'Failed to recreate database: {str(e)}'}
        
        return {'success': False, 'error': f'Recovery unsuccessful: {integrity_check.get("error")}'}
        
    except Exception as e:
        logging.error(f"Database recovery: Recovery process failed: {str(e)}")
        return {'success': False, 'error': f'Recovery process failed: {str(e)}'}


def get_disk_space(path):
    """Get available disk space for given path"""
    try:
        stat = os.statvfs(path)
        # Available space in bytes
        available = stat.f_bavail * stat.f_frsize
        # Total space in bytes  
        total = stat.f_blocks * stat.f_frsize
        # Used space in bytes
        used = total - available
        
        return {
            'available_bytes': available,
            'total_bytes': total,
            'used_bytes': used,
            'available_mb': round(available / (1024 * 1024), 2),
            'total_mb': round(total / (1024 * 1024), 2),
            'used_mb': round(used / (1024 * 1024), 2),
            'usage_percent': round((used / total) * 100, 2) if total > 0 else 0
        }
    except Exception as e:
        return {'error': f'Failed to get disk space: {str(e)}'}


def get_hourly_temperature_summary(user_id, limit=500, offset=0, date_from=None, date_to=None):
    """Get hourly temperature summary with min/max/avg values for chart performance optimization"""
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    query = DeviceData.query.filter_by(user_id=user_id)
    
    # Apply date filters if provided
    if date_from:
        try:
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass
    
    # Get all records
    records = query.order_by(DeviceData.timestamp.asc()).all()
    
    # Group by hour
    hourly_groups = defaultdict(list)
    for record in records:
        if record.timestamp:
            # Round timestamp to hour
            hour_key = record.timestamp.replace(minute=0, second=0, microsecond=0)
            hourly_groups[hour_key].append(record)
    
    # Calculate hourly aggregations
    hourly_summaries = []
    for hour_timestamp, hour_records in sorted(hourly_groups.items()):
        if not hour_records:
            continue
            
        def safe_aggregate(values, func):
            """Safely apply aggregation function to non-None values"""
            valid_values = [v for v in values if v is not None]
            return func(valid_values) if valid_values else None
        
        # Collect all temperature values for this hour
        room_temps = [r.room_temperature for r in hour_records]
        outdoor_temps = [r.outdoor_temperature for r in hour_records]
        flow_temps = [r.flow_temperature for r in hour_records]
        return_temps = [r.return_temperature for r in hour_records]
        tank_temps = [r.tank_temperature for r in hour_records]
        
        # Calculate delta T values
        delta_ts = []
        for r in hour_records:
            if r.flow_temperature is not None and r.return_temperature is not None:
                delta_ts.append(r.flow_temperature - r.return_temperature)
        
        hourly_summary = {
            'timestamp': hour_timestamp.isoformat() + 'Z',
            'period': 'hour',
            'data_points': len(hour_records),
            
            # Room temperature aggregation
            'room_temperature': {
                'avg': round(safe_aggregate(room_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(room_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(room_temps, min),
                'max': safe_aggregate(room_temps, max)
            } if any(t is not None for t in room_temps) else None,
            
            # Outdoor temperature aggregation
            'outdoor_temperature': {
                'avg': round(safe_aggregate(outdoor_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(outdoor_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(outdoor_temps, min),
                'max': safe_aggregate(outdoor_temps, max)
            } if any(t is not None for t in outdoor_temps) else None,
            
            # Flow temperature aggregation
            'flow_temperature': {
                'avg': round(safe_aggregate(flow_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(flow_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(flow_temps, min),
                'max': safe_aggregate(flow_temps, max)
            } if any(t is not None for t in flow_temps) else None,
            
            # Return temperature aggregation
            'return_temperature': {
                'avg': round(safe_aggregate(return_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(return_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(return_temps, min),
                'max': safe_aggregate(return_temps, max)
            } if any(t is not None for t in return_temps) else None,
            
            # Tank temperature aggregation
            'tank_temperature': {
                'avg': round(safe_aggregate(tank_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(tank_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(tank_temps, min),
                'max': safe_aggregate(tank_temps, max)
            } if any(t is not None for t in tank_temps) else None,
            
            # Delta T aggregation
            'delta_t': {
                'avg': round(safe_aggregate(delta_ts, lambda x: sum(x) / len(x)), 1) if safe_aggregate(delta_ts, lambda x: len(x)) else None,
                'min': safe_aggregate(delta_ts, min),
                'max': safe_aggregate(delta_ts, max)
            } if delta_ts else None
        }
        
        hourly_summaries.append(hourly_summary)
    
    # Apply limit and offset
    start_idx = offset
    end_idx = start_idx + limit if limit else len(hourly_summaries)
    
    return hourly_summaries[start_idx:end_idx]


def get_daily_temperature_summary(user_id, limit=200, offset=0, date_from=None, date_to=None):
    """Get daily temperature summary with min/max/avg values for chart performance optimization"""
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    query = DeviceData.query.filter_by(user_id=user_id)
    
    # Apply date filters if provided
    if date_from:
        try:
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass
    
    # Get all records
    records = query.order_by(DeviceData.timestamp.asc()).all()
    
    # Group by day
    daily_groups = defaultdict(list)
    for record in records:
        if record.timestamp:
            # Round timestamp to day (midnight)
            day_key = record.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            daily_groups[day_key].append(record)
    
    # Calculate daily aggregations
    daily_summaries = []
    for day_timestamp, day_records in sorted(daily_groups.items()):
        if not day_records:
            continue
            
        def safe_aggregate(values, func):
            """Safely apply aggregation function to non-None values"""
            valid_values = [v for v in values if v is not None]
            return func(valid_values) if valid_values else None
        
        # Collect all temperature values for this day
        room_temps = [r.room_temperature for r in day_records]
        outdoor_temps = [r.outdoor_temperature for r in day_records]
        flow_temps = [r.flow_temperature for r in day_records]
        return_temps = [r.return_temperature for r in day_records]
        tank_temps = [r.tank_temperature for r in day_records]
        
        # Calculate delta T values
        delta_ts = []
        for r in day_records:
            if r.flow_temperature is not None and r.return_temperature is not None:
                delta_ts.append(r.flow_temperature - r.return_temperature)
        
        daily_summary = {
            'timestamp': day_timestamp.isoformat() + 'Z',
            'period': 'day',
            'data_points': len(day_records),
            
            # Room temperature aggregation
            'room_temperature': {
                'avg': round(safe_aggregate(room_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(room_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(room_temps, min),
                'max': safe_aggregate(room_temps, max)
            } if any(t is not None for t in room_temps) else None,
            
            # Outdoor temperature aggregation
            'outdoor_temperature': {
                'avg': round(safe_aggregate(outdoor_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(outdoor_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(outdoor_temps, min),
                'max': safe_aggregate(outdoor_temps, max)
            } if any(t is not None for t in outdoor_temps) else None,
            
            # Flow temperature aggregation
            'flow_temperature': {
                'avg': round(safe_aggregate(flow_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(flow_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(flow_temps, min),
                'max': safe_aggregate(flow_temps, max)
            } if any(t is not None for t in flow_temps) else None,
            
            # Return temperature aggregation
            'return_temperature': {
                'avg': round(safe_aggregate(return_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(return_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(return_temps, min),
                'max': safe_aggregate(return_temps, max)
            } if any(t is not None for t in return_temps) else None,
            
            # Tank temperature aggregation
            'tank_temperature': {
                'avg': round(safe_aggregate(tank_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(tank_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(tank_temps, min),
                'max': safe_aggregate(tank_temps, max)
            } if any(t is not None for t in tank_temps) else None,
            
            # Delta T aggregation
            'delta_t': {
                'avg': round(safe_aggregate(delta_ts, lambda x: sum(x) / len(x)), 1) if safe_aggregate(delta_ts, lambda x: len(x)) else None,
                'min': safe_aggregate(delta_ts, min),
                'max': safe_aggregate(delta_ts, max)
            } if delta_ts else None
        }
        
        daily_summaries.append(daily_summary)
    
    # Apply limit and offset
    start_idx = offset
    end_idx = start_idx + limit if limit else len(daily_summaries)
    
    return daily_summaries[start_idx:end_idx]


def get_weekly_temperature_summary(user_id, limit=100, offset=0, date_from=None, date_to=None):
    """Get weekly temperature summary with min/max/avg values for chart performance optimization"""
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    query = DeviceData.query.filter_by(user_id=user_id)
    
    # Apply date filters if provided
    if date_from:
        try:
            if 'T' in date_from:
                date_from_obj = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            else:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(DeviceData.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            if 'T' in date_to:
                date_to_obj = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            else:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DeviceData.timestamp < date_to_obj)
        except ValueError:
            pass
    
    # Get all records
    records = query.order_by(DeviceData.timestamp.asc()).all()
    
    # Group by week (Monday as start of week)
    weekly_groups = defaultdict(list)
    for record in records:
        if record.timestamp:
            # Calculate the Monday of the week for this timestamp
            days_since_monday = record.timestamp.weekday()
            week_start = record.timestamp - timedelta(days=days_since_monday)
            week_key = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
            weekly_groups[week_key].append(record)
    
    # Calculate weekly aggregations
    weekly_summaries = []
    for week_timestamp, week_records in sorted(weekly_groups.items()):
        if not week_records:
            continue
            
        def safe_aggregate(values, func):
            """Safely apply aggregation function to non-None values"""
            valid_values = [v for v in values if v is not None]
            return func(valid_values) if valid_values else None
        
        # Collect all temperature values for this week
        room_temps = [r.room_temperature for r in week_records]
        outdoor_temps = [r.outdoor_temperature for r in week_records]
        flow_temps = [r.flow_temperature for r in week_records]
        return_temps = [r.return_temperature for r in week_records]
        tank_temps = [r.tank_temperature for r in week_records]
        
        # Calculate delta T values
        delta_ts = []
        for r in week_records:
            if r.flow_temperature is not None and r.return_temperature is not None:
                delta_ts.append(r.flow_temperature - r.return_temperature)
        
        weekly_summary = {
            'timestamp': week_timestamp.isoformat() + 'Z',
            'period': 'week',
            'data_points': len(week_records),
            
            # Room temperature aggregation
            'room_temperature': {
                'avg': round(safe_aggregate(room_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(room_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(room_temps, min),
                'max': safe_aggregate(room_temps, max)
            } if any(t is not None for t in room_temps) else None,
            
            # Outdoor temperature aggregation
            'outdoor_temperature': {
                'avg': round(safe_aggregate(outdoor_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(outdoor_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(outdoor_temps, min),
                'max': safe_aggregate(outdoor_temps, max)
            } if any(t is not None for t in outdoor_temps) else None,
            
            # Flow temperature aggregation
            'flow_temperature': {
                'avg': round(safe_aggregate(flow_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(flow_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(flow_temps, min),
                'max': safe_aggregate(flow_temps, max)
            } if any(t is not None for t in flow_temps) else None,
            
            # Return temperature aggregation
            'return_temperature': {
                'avg': round(safe_aggregate(return_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(return_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(return_temps, min),
                'max': safe_aggregate(return_temps, max)
            } if any(t is not None for t in return_temps) else None,
            
            # Tank temperature aggregation
            'tank_temperature': {
                'avg': round(safe_aggregate(tank_temps, lambda x: sum(x) / len(x)), 1) if safe_aggregate(tank_temps, lambda x: len(x)) else None,
                'min': safe_aggregate(tank_temps, min),
                'max': safe_aggregate(tank_temps, max)
            } if any(t is not None for t in tank_temps) else None,
            
            # Delta T aggregation
            'delta_t': {
                'avg': round(safe_aggregate(delta_ts, lambda x: sum(x) / len(x)), 1) if safe_aggregate(delta_ts, lambda x: len(x)) else None,
                'min': safe_aggregate(delta_ts, min),
                'max': safe_aggregate(delta_ts, max)
            } if delta_ts else None
        }
        
        weekly_summaries.append(weekly_summary)
    
    # Apply limit and offset
    start_idx = offset
    end_idx = start_idx + limit if limit else len(weekly_summaries)
    
    return weekly_summaries[start_idx:end_idx]


def is_database_error_recoverable(error_msg):
    """Check if a database error is recoverable"""
    recoverable_errors = [
        'readonly database',
        'database is locked', 
        'attempt to write a readonly database',
        'database disk image is malformed',
        'no such table'
    ]
    
    error_lower = str(error_msg).lower()
    return any(recoverable_error in error_lower for recoverable_error in recoverable_errors)

# Web User Management Functions

def create_web_user(username, email, password, role='user'):
    """Create a new web user for authentication"""
    user = WebUser(username=username, email=email, role=role)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    return user

def get_web_user_by_username(username):
    """Get web user by username"""
    return WebUser.query.filter_by(username=username).first()

def get_web_user_by_email(email):
    """Get web user by email"""
    return WebUser.query.filter_by(email=email).first()

def authenticate_web_user(username_or_email, password):
    """Authenticate a web user and return user object if valid"""
    # Try to find user by username or email
    user = get_web_user_by_username(username_or_email)
    if not user:
        user = get_web_user_by_email(username_or_email)
    
    if not user:
        return None
    
    if not user.is_active:
        return None
        
    if user.is_locked():
        return None
    
    if user.check_password(password):
        user.reset_failed_login()
        db.session.commit()
        return user
    else:
        user.increment_failed_login()
        db.session.commit()
        return None

def create_web_session(user_id, session_id, ip_address=None, user_agent=None, hours=24):
    """Create a new web session"""
    from datetime import timedelta
    
    session = WebSession(
        session_id=session_id,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=datetime.utcnow() + timedelta(hours=hours)
    )
    
    db.session.add(session)
    db.session.commit()
    
    return session

def get_web_session(session_id):
    """Get web session by session ID"""
    return WebSession.query.filter_by(session_id=session_id, is_active=True).first()

def cleanup_expired_sessions():
    """Clean up expired web sessions"""
    expired_sessions = WebSession.query.filter(
        WebSession.expires_at < datetime.utcnow()
    ).all()
    
    for session in expired_sessions:
        session.is_active = False
    
    db.session.commit()
    
    return len(expired_sessions)

def has_admin_user():
    """Check if there's at least one admin user"""
    return WebUser.query.filter_by(role='admin', is_active=True).count() > 0

def get_all_web_users():
    """Get all web users (admin function)"""
    return WebUser.query.all()


# API Settings Functions
def get_api_settings():
    """Get current API settings, create default if none exist"""
    settings = APISettings.query.first()
    if not settings:
        # Create default settings
        settings = APISettings(
            fetch_interval_minutes=10,
            api_enabled=True
        )
        db.session.add(settings)
        db.session.commit()
    return settings

def update_api_settings(fetch_interval_minutes=None, api_enabled=None, user_id=None):
    """Update API settings"""
    settings = get_api_settings()
    
    if fetch_interval_minutes is not None:
        # Enforce minimum interval of 5 minutes
        if fetch_interval_minutes < 5:
            raise ValueError("Fetch interval must be at least 5 minutes")
        settings.fetch_interval_minutes = fetch_interval_minutes
    
    if api_enabled is not None:
        settings.api_enabled = api_enabled
    
    settings.updated_at = datetime.utcnow()
    if user_id:
        settings.updated_by_user_id = user_id
    
    db.session.commit()
    return settings

def get_fetch_interval_seconds():
    """Get the current fetch interval in seconds"""
    settings = get_api_settings()
    if not settings.api_enabled:
        return None  # API disabled
    return settings.fetch_interval_minutes * 60

def is_api_enabled():
    """Check if API communications are enabled"""
    settings = get_api_settings()
    return settings.api_enabled


# Schedule Management Functions

def create_schedule(name, device_id, user_id, schedule_type, priority=1):
    """Create a new device schedule"""
    schedule = DeviceSchedule(
        name=name,
        device_id=device_id,
        user_id=user_id,
        schedule_type=schedule_type,
        priority=priority
    )
    
    db.session.add(schedule)
    db.session.commit()
    return schedule

def get_schedules(user_id=None, device_id=None, active_only=True):
    """Get schedules with optional filtering"""
    query = DeviceSchedule.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    if device_id:
        query = query.filter_by(device_id=device_id)
    if active_only:
        query = query.filter_by(is_active=True)
    
    return query.order_by(DeviceSchedule.priority, DeviceSchedule.created_at).all()

def get_schedule_by_id(schedule_id):
    """Get a specific schedule by ID"""
    return DeviceSchedule.query.get(schedule_id)

def update_schedule(schedule_id, **kwargs):
    """Update schedule fields"""
    schedule = DeviceSchedule.query.get(schedule_id)
    if not schedule:
        return None
    
    for key, value in kwargs.items():
        if hasattr(schedule, key):
            setattr(schedule, key, value)
    
    schedule.updated_at = datetime.utcnow()
    db.session.commit()
    return schedule

def delete_schedule(schedule_id):
    """Delete a schedule and all its rules and logs"""
    schedule = DeviceSchedule.query.get(schedule_id)
    if not schedule:
        return False
    
    db.session.delete(schedule)
    db.session.commit()
    return True

def toggle_schedule(schedule_id):
    """Toggle schedule active/inactive status"""
    schedule = DeviceSchedule.query.get(schedule_id)
    if not schedule:
        return None
    
    schedule.is_active = not schedule.is_active
    schedule.updated_at = datetime.utcnow()
    db.session.commit()
    return schedule

def add_schedule_rule(schedule_id, time_of_day, target_value, day_of_week=None, conditions_json=None):
    """Add a rule to a schedule"""
    from datetime import time
    
    # Convert time string to time object if needed
    if isinstance(time_of_day, str):
        time_parts = time_of_day.split(':')
        hour = int(time_parts[0])
        minute = int(time_parts[1])
        # Ignore seconds if present
        time_of_day = time(hour, minute)
    
    rule = ScheduleRule(
        schedule_id=schedule_id,
        day_of_week=day_of_week,
        time_of_day=time_of_day,
        target_value=target_value,
        conditions_json=conditions_json
    )
    
    db.session.add(rule)
    db.session.commit()
    return rule

def get_schedule_rules(schedule_id):
    """Get all rules for a schedule"""
    return ScheduleRule.query.filter_by(schedule_id=schedule_id).all()

def delete_schedule_rule(rule_id):
    """Delete a schedule rule"""
    rule = ScheduleRule.query.get(rule_id)
    if not rule:
        return False
    
    db.session.delete(rule)
    db.session.commit()
    return True

def log_schedule_execution(schedule_id, success, error_message=None, device_response_json=None):
    """Log the execution of a schedule"""
    log_entry = ScheduleExecutionLog(
        schedule_id=schedule_id,
        success=success,
        error_message=error_message,
        device_response_json=device_response_json
    )
    
    db.session.add(log_entry)
    db.session.commit()
    return log_entry

def get_schedule_execution_history(schedule_id=None, limit=100):
    """Get schedule execution history"""
    query = ScheduleExecutionLog.query
    
    if schedule_id:
        query = query.filter_by(schedule_id=schedule_id)
    
    return query.order_by(ScheduleExecutionLog.executed_at.desc()).limit(limit).all()


def get_next_schedules():
    """Get the next upcoming schedule executions for heating, hot water, and holiday.
    Returns a dict with keys 'next_heating', 'next_hotwater', and optionally 'next_holiday'.
    Each value is a dict containing: schedule_id, rule_id, schedule_name, time, target_value, next_execution, is_tomorrow, device_id, days_away.
    """
    from datetime import datetime, time, timedelta
    
    try:
        # Get current time in UTC (matching schedule engine)
        current_time = datetime.utcnow()
        current_weekday = current_time.weekday()
        current_time_only = current_time.time()
        
        # Get all active schedules
        schedules = get_schedules(active_only=True)
        
        next_heating = None
        next_hotwater = None
        next_holiday = None
        
        for schedule in schedules:
            for rule in schedule.rules:
                # Calculate when this rule will next execute (looking up to 7 days ahead)
                rule_time = rule.time_of_day
                rule_day_of_week = rule.day_of_week
                
                next_execution = None
                days_away = None
                
                if rule_day_of_week is None:
                    # Daily rule - check if it's later today or tomorrow
                    today_execution = datetime.combine(current_time.date(), rule_time)
                    if today_execution > current_time:
                        next_execution = today_execution
                        days_away = 0
                    else:
                        next_execution = datetime.combine(current_time.date() + timedelta(days=1), rule_time)
                        days_away = 1
                else:
                    # Specific day of week rule - calculate days until next occurrence
                    days_until_rule = (rule_day_of_week - current_weekday) % 7
                    if days_until_rule == 0:
                        # Rule is today - check if it's already passed
                        today_execution = datetime.combine(current_time.date(), rule_time)
                        if today_execution > current_time:
                            next_execution = today_execution
                            days_away = 0
                        else:
                            # Already passed today, next occurrence is next week
                            next_execution = datetime.combine(current_time.date() + timedelta(days=7), rule_time)
                            days_away = 7
                    else:
                        # Rule is on a future day this week
                        next_execution = datetime.combine(current_time.date() + timedelta(days=days_until_rule), rule_time)
                        days_away = days_until_rule
                
                if next_execution is None:
                    continue
                
                # Maintain backward compatibility with is_tomorrow field
                is_tomorrow = (days_away == 1)
                
                # Create schedule info
                schedule_info = {
                    'schedule_id': schedule.id,
                    'rule_id': rule.id,
                    'schedule_name': schedule.name,
                    'time': rule_time,
                    'target_value': rule.target_value,
                    'next_execution': next_execution,
                    'is_tomorrow': is_tomorrow,
                    'days_away': days_away,
                    'device_id': schedule.device_id
                }
                
                # Store the earliest upcoming schedule for each type
                if schedule.schedule_type == 'temperature':
                    if next_heating is None or next_execution < next_heating['next_execution']:
                        next_heating = schedule_info
                elif schedule.schedule_type == 'hot_water':
                    if next_hotwater is None or next_execution < next_hotwater['next_execution']:
                        next_hotwater = schedule_info
                elif schedule.schedule_type == 'holiday':
                    if next_holiday is None or next_execution < next_holiday['next_execution']:
                        next_holiday = schedule_info
        
        result = {
            'next_heating': next_heating,
            'next_hotwater': next_hotwater,
            'current_time': current_time
        }
        if next_holiday:
            result['next_holiday'] = next_holiday
        return result
        
    except Exception as e:
        # Return empty result on error
        return {
            'next_heating': None,
            'next_hotwater': None,
            'current_time': datetime.utcnow(),
            'error': str(e)
        }


# Device Configuration Management Functions

def get_device_config(device_id):
    """Get device configuration by device ID"""
    return DeviceConfig.query.filter_by(device_id=device_id).first()

def create_device_config(device_id, timezone='UTC', device_name=None):
    """Create a new device configuration"""
    config = DeviceConfig(
        device_id=device_id,
        timezone=timezone,
        device_name=device_name
    )
    db.session.add(config)
    db.session.commit()
    return config

def update_device_config(device_id, timezone=None, device_name=None):
    """Update device configuration"""
    config = get_device_config(device_id)
    if not config:
        # Create if doesn't exist
        return create_device_config(device_id, timezone or 'UTC', device_name)
    
    if timezone:
        config.timezone = timezone
    if device_name:
        config.device_name = device_name
    
    config.updated_at = datetime.utcnow()
    db.session.commit()
    return config

def get_device_timezone(device_id):
    """Get timezone for a device, defaults to UTC"""
    config = get_device_config(device_id)
    return config.timezone if config else 'UTC'

def convert_device_time_to_utc(time_str, device_id):
    """Convert device local time to UTC time
    Args:
        time_str: Time string in HH:MM format (24-hour)
        device_id: Device ID to get timezone
    Returns:
        UTC time string in HH:MM format
    """
    device_timezone = get_device_timezone(device_id)
    
    if device_timezone == 'UTC':
        return time_str
    
    try:
        import pytz
        from datetime import datetime, time, date
        
        # Parse input time
        hour, minute = map(int, time_str.split(':'))
        device_time = time(hour, minute)
        
        # Create datetime in device timezone for today
        device_tz = pytz.timezone(device_timezone)
        today = date.today()
        device_dt = device_tz.localize(datetime.combine(today, device_time))
        
        # Convert to UTC
        utc_dt = device_dt.astimezone(pytz.UTC)
        
        # Return as HH:MM string
        return utc_dt.strftime('%H:%M')
        
    except ImportError:
        # pytz not available, fallback to original time
        return time_str
    except (ValueError, Exception) as e:
        # Fallback to original time if conversion fails
        return time_str

def convert_utc_to_device_time(utc_time, device_id):
    """Convert UTC time to device local time
    Args:
        utc_time: UTC time object or HH:MM string
        device_id: Device ID to get timezone
    Returns:
        Device local time string in HH:MM format
    """
    device_timezone = get_device_timezone(device_id)
    
    if device_timezone == 'UTC':
        if isinstance(utc_time, str):
            return utc_time
        return utc_time.strftime('%H:%M')
    
    try:
        import pytz
        from datetime import datetime, time, date
        
        device_tz = pytz.timezone(device_timezone)
        
        if isinstance(utc_time, str):
            # Parse string time
            hour, minute = map(int, utc_time.split(':'))
            utc_time = time(hour, minute)
        
        # Create UTC datetime for today
        today = date.today()
        utc_dt = pytz.UTC.localize(datetime.combine(today, utc_time))
        
        # Convert to device timezone
        device_dt = utc_dt.astimezone(device_tz)
        
        # Return as HH:MM string
        return device_dt.strftime('%H:%M')
        
    except ImportError:
        # pytz not available, fallback to original time
        if isinstance(utc_time, str):
            return utc_time
        return utc_time.strftime('%H:%M')
    except (ValueError, Exception) as e:
        # Fallback to original time if conversion fails
        if isinstance(utc_time, str):
            return utc_time
        return utc_time.strftime('%H:%M')

def get_common_timezones():
    """Get list of timezones for UI dropdowns.

    Prefer pytz.common_timezones (comprehensive but curated) to cover all
    major/commonly used IANA zones. Fall back to a smaller static list if
    pytz is unavailable for any reason.
    """
    try:
        import pytz
        # Start with pytz.common_timezones for broad coverage
        tzs = list(pytz.common_timezones)
        # Keep 'UTC' at the top, sort the rest alphabetically for usability
        tzs_sorted = ['UTC'] + sorted(t for t in tzs if t != 'UTC')
        return tzs_sorted
    except Exception:
        # Fallback to previous curated subset
        return [
            'UTC',
            'America/New_York',      # Eastern Time
            'America/Chicago',       # Central Time
            'America/Denver',        # Mountain Time
            'America/Los_Angeles',   # Pacific Time
            'America/Toronto',       # Eastern Time (Canada)
            'America/Vancouver',     # Pacific Time (Canada)
            'Europe/London',         # GMT/BST
            'Europe/Paris',          # CET/CEST
            'Europe/Berlin',         # CET/CEST
            'Europe/Rome',           # CET/CEST
            'Europe/Madrid',         # CET/CEST
            'Europe/Amsterdam',      # CET/CEST
            'Europe/Brussels',       # CET/CEST
            'Europe/Zurich',         # CET/CEST
            'Asia/Tokyo',            # JST
            'Asia/Shanghai',         # CST
            'Asia/Hong_Kong',        # HKT
            'Asia/Singapore',        # SGT
            'Asia/Dubai',            # GST
            'Australia/Sydney',      # AEST/AEDT
            'Australia/Melbourne',   # AEST/AEDT
            'Australia/Perth',       # AWST
            'Pacific/Auckland',      # NZST/NZDT
        ]
