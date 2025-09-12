#!/usr/bin/env python3
"""
Authentication utilities and decorators for MELCloud Web Interface
"""

from functools import wraps
from flask import request, jsonify, redirect, url_for, flash, session, current_app
from flask_login import current_user, login_required as flask_login_required
import secrets
import logging
from datetime import datetime, timedelta
from database import (
    WebUser, WebSession, authenticate_web_user, create_web_session, 
    get_web_session, cleanup_expired_sessions, has_admin_user, db
)

# Rate limiting for login attempts
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=30)

def clean_login_attempts():
    """Clean up old login attempt records"""
    global login_attempts
    current_time = datetime.utcnow()
    
    # Remove entries older than lockout duration
    expired_ips = []
    for ip, data in login_attempts.items():
        if current_time - data['first_attempt'] > LOCKOUT_DURATION:
            expired_ips.append(ip)
    
    for ip in expired_ips:
        del login_attempts[ip]

def is_ip_locked(ip_address):
    """Check if IP address is locked due to too many failed attempts"""
    clean_login_attempts()
    
    if ip_address not in login_attempts:
        return False
    
    data = login_attempts[ip_address]
    if data['attempts'] >= MAX_LOGIN_ATTEMPTS:
        time_since_first = datetime.utcnow() - data['first_attempt']
        if time_since_first < LOCKOUT_DURATION:
            return True
        else:
            # Reset after lockout period
            del login_attempts[ip_address]
            return False
    
    return False

def record_failed_login(ip_address):
    """Record a failed login attempt for an IP address"""
    clean_login_attempts()
    
    if ip_address not in login_attempts:
        login_attempts[ip_address] = {
            'attempts': 1,
            'first_attempt': datetime.utcnow()
        }
    else:
        login_attempts[ip_address]['attempts'] += 1

def reset_login_attempts(ip_address):
    """Reset login attempts for an IP after successful login"""
    if ip_address in login_attempts:
        del login_attempts[ip_address]

def generate_csrf_token():
    """Generate a CSRF token for forms"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    if 'csrf_token' not in session:
        return False
    return secrets.compare_digest(session['csrf_token'], token)

def login_required(f):
    """Decorator to require login for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
            else:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
            else:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
        
        if not current_user.is_admin():
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            else:
                flash('Admin access required for this page.', 'error')
                return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def optional_login(f):
    """Decorator for routes that work both with and without login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # This decorator doesn't block access, just ensures user context is available
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    """Get the real client IP address"""
    # Check for forwarded headers first (if behind proxy)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def log_security_event(event_type, user_id=None, ip_address=None, details=None):
    """Log security-related events"""
    try:
        ip = ip_address or get_client_ip()
        user_info = f"User {user_id}" if user_id else "Anonymous"
        details_str = f" - {details}" if details else ""
        
        logging.warning(f"SECURITY EVENT [{event_type}]: {user_info} from {ip}{details_str}")
    except Exception as e:
        logging.error(f"Failed to log security event: {e}")

def validate_password_strength(password):
    """Validate password meets minimum security requirements"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    # Check for common weak passwords
    weak_passwords = [
        'password', '12345678', 'qwerty', 'abc123', 
        'password123', '123456789', 'letmein', 'welcome'
    ]
    
    if password.lower() in weak_passwords:
        errors.append("Password is too common, please choose a stronger password")
    
    return errors

def create_secure_session(user, remember=False):
    """Create a secure session for a user"""
    try:
        # Generate secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Set session duration (24 hours default, 30 days if remember me)
        hours = 720 if remember else 24  # 30 days vs 24 hours
        
        # Create session in database
        web_session = create_web_session(
            user_id=user.id,
            session_id=session_id,
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')[:500],  # Truncate long user agents
            hours=hours
        )
        
        # Set Flask session
        session['user_id'] = user.id
        session['session_id'] = session_id
        session.permanent = remember
        
        if remember:
            current_app.permanent_session_lifetime = timedelta(days=30)
        else:
            current_app.permanent_session_lifetime = timedelta(hours=24)
        
        log_security_event('LOGIN_SUCCESS', user.id)
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to create secure session: {e}")
        return False

def destroy_session():
    """Destroy current session securely"""
    try:
        if 'session_id' in session:
            # Mark session as inactive in database
            web_session = get_web_session(session['session_id'])
            if web_session:
                web_session.is_active = False
                db.session.commit()
        
        # Clear Flask session
        session.clear()
        
        log_security_event('LOGOUT_SUCCESS', getattr(current_user, 'id', None))
        
    except Exception as e:
        logging.error(f"Failed to destroy session: {e}")

def require_setup():
    """Decorator to redirect to setup if no admin users exist"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_admin_user():
                if request.is_json:
                    return jsonify({'error': 'Setup required', 'redirect': '/setup'}), 302
                else:
                    return redirect(url_for('setup'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def cleanup_old_sessions():
    """Clean up expired sessions and old login attempts"""
    try:
        expired_count = cleanup_expired_sessions()
        clean_login_attempts()
        
        if expired_count > 0:
            logging.info(f"Cleaned up {expired_count} expired sessions")
            
    except Exception as e:
        logging.error(f"Failed to cleanup old sessions: {e}")

# Password complexity requirements for display
PASSWORD_REQUIREMENTS = [
    "At least 8 characters long",
    "Contains uppercase and lowercase letters", 
    "Contains at least one number",
    "Not a common password"
]