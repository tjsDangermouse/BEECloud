#!/usr/bin/env python3
"""
MELCloud Web Interface
Flask app to display MELCloud data in a web interface
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, send_from_directory, make_response

# Application version
try:
    # Preferred import when 'src' is a package / on PYTHONPATH
    from src.version import __version__
except Exception:
    # Fallback for direct execution without package context
    import sys as _sys
    _sys.path.insert(0, "src")
    from version import __version__
try:
    from flask_compress import Compress  # Optional; app runs without it
    _compress_available = True
except Exception:
    Compress = None
    _compress_available = False
from flask_login import LoginManager, login_user, logout_user, login_required as flask_login_required, current_user
import asyncio
import aiohttp
import json
import urllib.parse
import urllib.request
import time
import os
import threading
import logging
from datetime import datetime
import hashlib
import argparse
from melcloud_api import get_melcloud_data, MELCloudAPI
# Command functions are defined in this module
from schedule_engine import get_schedule_engine, start_schedule_engine, stop_schedule_engine, is_schedule_engine_running
from database import (
    db, init_database, get_user, create_user, update_user_credentials,
    store_device_data, get_device_data_history, get_latest_device_data,
    get_latest_devices_for_dashboard, get_daily_energy_summary, check_database_integrity, 
    recover_database, get_disk_space, is_database_error_recoverable,
    get_hourly_temperature_summary, get_daily_temperature_summary, get_weekly_temperature_summary,
    WebUser, create_web_user, authenticate_web_user, has_admin_user, get_web_user_by_username,
    encrypt_password, decrypt_password, get_decrypted_melcloud_password,
    get_encryption_status,
    cleanup_expired_sessions,
    # Schedule management functions
    create_schedule, get_schedules, get_schedule_by_id, update_schedule, delete_schedule,
    toggle_schedule, add_schedule_rule, get_schedule_rules, delete_schedule_rule,
    log_schedule_execution, get_schedule_execution_history, get_next_schedules,
    # Device configuration functions
    get_device_config, create_device_config, update_device_config, get_device_timezone,
    convert_device_time_to_utc, convert_utc_to_device_time, get_common_timezones
)
from auth import (
    login_required, admin_required, require_setup, generate_csrf_token, validate_csrf_token,
    get_client_ip, log_security_event, validate_password_strength, create_secure_session,
    destroy_session, is_ip_locked, record_failed_login, reset_login_attempts, cleanup_old_sessions
)

app = Flask(__name__)
app.jinja_env.globals["APP_VERSION"] = __version__
if _compress_available and Compress is not None:
    try:
        Compress(app)
    except Exception:
        # Fail open if compression init fails
        pass

# Database configuration
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'melcloud.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'timeout': 30,
        'check_same_thread': False
    }
}
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
# Long-lived caching for static files (tuned for production)
try:
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year for /static/*
except Exception:
    pass

# Initialize database
init_database(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    try:
        return WebUser.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

def migrate_database():
    """Run database migrations for new columns"""
    try:
        with app.app_context():
            from sqlalchemy import text
            
            # Check if last_legionella_activation_time column exists
            with db.engine.connect() as connection:
                try:
                    connection.execute(text("SELECT last_legionella_activation_time FROM device_data LIMIT 1"))
                    logging.info("Database migration: last_legionella_activation_time column already exists")
                except Exception:
                    # Column doesn't exist, add it
                    connection.execute(text("ALTER TABLE device_data ADD COLUMN last_legionella_activation_time DATETIME"))
                    connection.commit()
                    logging.info("Database migration: Added last_legionella_activation_time column")
            
            # Ensure users.password_encrypted exists
            with db.engine.connect() as connection:
                try:
                    connection.execute(text("SELECT password_encrypted FROM users LIMIT 1"))
                    logging.info("Database migration: users.password_encrypted already exists")
                except Exception:
                    connection.execute(text("ALTER TABLE users ADD COLUMN password_encrypted TEXT"))
                    connection.commit()
                    logging.info("Database migration: Added users.password_encrypted column")

            # Backfill encryption for existing plaintext passwords (best-effort)
            try:
                with db.engine.connect() as connection:
                    rows = connection.execute(text(
                        "SELECT id, password_plain FROM users WHERE (password_encrypted IS NULL OR password_encrypted = '') AND password_plain IS NOT NULL AND password_plain != ''"
                    )).fetchall()
                    updated = 0
                    for row in rows:
                        enc = encrypt_password(row[1])
                        if enc:
                            connection.execute(text(
                                "UPDATE users SET password_encrypted = :enc, password_plain = '' WHERE id = :id"
                            ), {"enc": enc, "id": row[0]})
                            updated += 1
                    if updated:
                        connection.commit()
                        logging.info(f"Database migration: Encrypted MELCloud passwords for {updated} user(s) and cleared plaintext")
            except Exception as e:
                logging.warning(f"Database migration: Could not backfill encrypted passwords: {e}")
    except Exception as e:
        logging.error(f"Database migration failed: {str(e)}")
        # Don't crash the app on migration failure

# Global variables to store data and API instance
cached_data = None
last_update = 0
api_instance = None

# Auto-fetch configuration
auto_fetch_enabled = True
auto_fetch_thread = None

# Error tracking for service restart
db_error_count = 0
max_db_errors = 3
last_db_error_time = 0
service_restart_count = 0
startup_bypass_rate_limit = False  # Will be set to True only on actual startup

# Simple in-memory cache for weather lookups
_weather_cache = {}
_WEATHER_CACHE_TTL_SECONDS = 600  # 10 minutes

# =============================
# Service Worker endpoints
# =============================
@app.route('/sw.js')
def service_worker():
    """Serve the Service Worker script at the root scope so it can control the whole app."""
    try:
        resp = make_response(app.send_static_file('js/sw.js'))
        resp.headers['Service-Worker-Allowed'] = '/'
        resp.headers['Cache-Control'] = 'no-cache'
        resp.mimetype = 'application/javascript'
        return resp
    except Exception as e:
        logging.error(f"SW serve error: {e}")
        return jsonify({'error': 'Service worker not found'}), 404


@app.after_request
def _sw_headers(response):
    try:
        if request.path in ('/static/js/sw.js', '/sw.js'):
            response.headers['Service-Worker-Allowed'] = '/'
            response.headers['Cache-Control'] = 'no-cache'
            response.headers.setdefault('Content-Type', 'application/javascript')
    except Exception:
        pass
    return response

# ============================================================================
# HTTP Caching Helpers (ETag + Cache-Control)
# ============================================================================

def _build_etag(*parts) -> str:
    raw = "|".join(str(p) for p in parts if p is not None)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

def _is_not_modified(etag: str) -> bool:
    try:
        inm = request.if_none_match
        return bool(inm and inm.contains(etag))
    except Exception:
        return False

def _apply_cache_headers(response, etag: str, max_age: int = 60, swr: int = 120):
    try:
        response.set_etag(etag)
    except Exception:
        response.headers['ETag'] = etag
    response.headers['Cache-Control'] = f"public, max-age={max_age}, stale-while-revalidate={swr}"

# ============================================================================
# MELCloud Command Execution Functions
# ============================================================================

async def execute_temperature_command(email: str, password: str, device_id: int, temperature: float, bypass_rate_limit: bool = False):
    """Execute temperature setting command via MELCloud API"""
    try:
        api = MELCloudAPI(email=email, password=password)
        if bypass_rate_limit:
            api.bypass_rate_limit = True
        
        async with aiohttp.ClientSession() as session:
            # Login
            login_result = await api.login(session)
            if not login_result["success"]:
                return {
                    "success": False,
                    "error": f"Authentication failed: {login_result.get('error')}"
                }
            
            # Send temperature command
            result = await api.set_temperature(session, device_id, temperature)
            return result
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Command execution failed: {str(e)}"
        }

async def execute_hot_water_command(email: str, password: str, device_id: int, enable: bool, bypass_rate_limit: bool = False):
    """Execute hot water boost command via MELCloud API"""
    try:
        api = MELCloudAPI(email=email, password=password)
        if bypass_rate_limit:
            api.bypass_rate_limit = True
        
        async with aiohttp.ClientSession() as session:
            # Login
            login_result = await api.login(session)
            if not login_result["success"]:
                return {
                    "success": False,
                    "error": f"Authentication failed: {login_result.get('error')}"
                }
            
            # Send hot water command
            result = await api.force_hot_water(session, device_id, enable)
            return result
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Command execution failed: {str(e)}"
        }

async def execute_holiday_mode_command(email: str, password: str, device_id: int, enable: bool, bypass_rate_limit: bool = False):
    """Execute holiday mode command via MELCloud API"""
    try:
        api = MELCloudAPI(email=email, password=password)
        if bypass_rate_limit:
            api.bypass_rate_limit = True
        
        async with aiohttp.ClientSession() as session:
            # Login
            login_result = await api.login(session)
            if not login_result["success"]:
                return {
                    "success": False,
                    "error": f"Authentication failed: {login_result.get('error')}"
                }
            
            # Send holiday mode command
            result = await api.set_holiday_mode(session, device_id, enable)
            return result
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Command execution failed: {str(e)}"
        }

async def debug_temperature_command(email: str, password: str, device_id: int, temperature: float):
    """Debug function to show what temperature command would be sent (no actual command sent)"""
    try:
        api = MELCloudAPI(email=email, password=password)
        
        async with aiohttp.ClientSession() as session:
            # Login
            login_result = await api.login(session)
            if not login_result["success"]:
                return {
                    "success": False,
                    "error": f"Authentication failed: {login_result.get('error')}"
                }
            
            # Get the raw device state from MELCloud (not processed data)
            device_state_result = await api.get_device_state(session, device_id, bypass_rate_limit=True)
            if not device_state_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to get device state: {device_state_result.get('error')}",
                    "debug_info": device_state_result.get('debug_available_devices'),
                    "total_devices": device_state_result.get('total_devices')
                }
            
            # The device state contains the raw MELCloud data with original field names
            target_device = device_state_result.get("device_data")
            if not target_device:
                return {
                    "success": False,
                    "error": "No device data found in response"
                }
                
            # Enhanced debugging to examine device structure
            device_debug_info = {
                "target_device_keys": list(target_device.keys()) if target_device else [],
                "target_device_sample": dict(list(target_device.items())[:20]) if target_device else {},
                "device_data_keys": list(target_device.get("device_data", {}).keys()) if target_device else [],
                "current_data_keys": list(target_device.get("current_data", {}).keys()) if target_device else [],
                "device_data_content": target_device.get("device_data") if target_device else {},
                "current_data_content": target_device.get("current_data") if target_device else {},
                "all_temperature_fields_direct": {k: v for k, v in target_device.items() if 'temp' in k.lower()} if target_device else {},
                "all_set_fields_direct": {k: v for k, v in target_device.items() if k.lower().startswith('set')} if target_device else {},
                "power_related_fields": {k: v for k, v in target_device.items() if 'power' in k.lower() or 'mode' in k.lower()} if target_device else {},
                "effective_flags_field": target_device.get("EffectiveFlags") if target_device else None
            }
            
            # The control fields are in the current_data object, not directly on the device
            current_state = target_device.get("current_data", {})
            if not current_state:
                # Fallback to the device object itself if current_data is empty
                current_state = target_device
                
            # Show what would be modified
            rounded_temp = api.round_temperature(temperature)
            
            # Show before/after comparison - check both processed and raw field names
            before_temp = (current_state.get("SetTemperatureZone1") or 
                          current_state.get("set_temperature") or "Unknown")
            before_flags = (current_state.get("EffectiveFlags") or 
                           current_state.get("effective_flags") or 0)
            
            new_flags = before_flags | 0x200000080  # pymelcloud flag for Zone 1 temp
            
            return {
                "success": True,
                "dry_run": True,
                "device_structure_debug": device_debug_info,
                "current_device_state": {
                    "DeviceID": target_device.get("device_id", device_id),
                    "DeviceType": target_device.get("device_type"),
                    "DeviceName": target_device.get("device_name"),
                    "Power": current_state.get("Power") or current_state.get("power"),
                    "SetTemperatureZone1": before_temp,
                    "EffectiveFlags": before_flags,
                    "ForcedHotWaterMode": (current_state.get("ForcedHotWaterMode") or 
                                         current_state.get("forced_hot_water")),
                    "HolidayMode": (current_state.get("HolidayMode") or 
                                   current_state.get("holiday_mode"))
                },
                "raw_device_fields": {
                    "all_temperature_fields": {k: v for k, v in current_state.items() if 'temp' in k.lower()},
                    "all_set_fields": {k: v for k, v in current_state.items() if k.lower().startswith('set')},
                    "device_keys_sample": list(current_state.keys())[:20]  # First 20 keys to see structure
                },
                "proposed_changes": {
                    "SetTemperatureZone1": f"{before_temp} → {rounded_temp}",
                    "EffectiveFlags": f"0x{before_flags:X} → 0x{new_flags:X} (added 0x200000080)",
                    "HasPendingCommand": "True (will be set)"
                },
                "safety_checks": {
                    "device_type_check": "Will verify device is Air-to-Water (DeviceType=1)",
                    "temperature_range": f"{temperature}°C rounded to {rounded_temp}°C (10-30°C range)",
                    "field_modified": "Only SetTemperatureZone1 will be changed",
                    "flow_temperature": "NEVER modified (safety confirmed)"
                }
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Debug command failed: {str(e)}"
        }

async def debug_hot_water_command(email: str, password: str, device_id: int, enable: bool):
    """Debug function to show what hot water command would be sent (no actual command sent)"""
    try:
        api = MELCloudAPI(email=email, password=password)
        
        async with aiohttp.ClientSession() as session:
            # Login
            login_result = await api.login(session)
            if not login_result["success"]:
                return {
                    "success": False,
                    "error": f"Authentication failed: {login_result.get('error')}"
                }
            
            # Get the device state from MELCloud
            device_state_result = await api.get_device_state(session, device_id, bypass_rate_limit=True)
            if not device_state_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to get device state: {device_state_result.get('error')}",
                    "debug_info": device_state_result.get('debug_available_devices'),
                    "total_devices": device_state_result.get('total_devices')
                }
            
            # Get device data
            device_data = device_state_result.get("device_data")
            current_data = device_data.get("current_data", {})
            
            # Show current state
            current_hot_water = current_data.get("forced_hot_water", False)
            
            # Build the command that would be sent
            new_state = {
                "DeviceID": device_data.get("device_id"),
                "DeviceType": device_data.get("device_type", 1),
                "ForcedHotWaterMode": enable,
                "EffectiveFlags": 0x10000,
                "HasPendingCommand": True,
                # Copy other required fields if they exist
                "Power": current_data.get("power", True),
                # Preserve all temperature settings
                "SetTemperatureZone1": current_data.get("set_temperature"),
                "SetTemperatureZone2": current_data.get("set_temperature_zone2"),
                "SetTankWaterTemperature": current_data.get("set_tank_temperature"),
                # Preserve operation mode settings
                "OperationMode": current_data.get("operation_mode"),
                "OperationModeZone1": current_data.get("operation_mode_zone1"),
                "OperationModeZone2": current_data.get("operation_mode_zone2"),
                # Preserve other mode settings
                "EcoHotWater": current_data.get("eco_hot_water", False),
                "HolidayMode": current_data.get("holiday_mode", False)
            }
            
            return {
                "success": True,
                "current_device_state": {
                    "device_id": device_data.get("device_id"),
                    "device_name": device_data.get("device_name"),
                    "current_hot_water_boost": current_hot_water,
                    "current_temperature": current_data.get("set_temperature"),
                    "current_power": current_data.get("power")
                },
                "proposed_changes": {
                    "ForcedHotWaterMode": f"{current_hot_water} → {enable}",
                    "DeviceID": device_data.get("device_id"),
                    "DeviceType": device_data.get("device_type", 1),
                    "EffectiveFlags": "0x10000 (hot water boost flag)",
                    "HasPendingCommand": "True (will be set)"
                },
                "safety_checks": {
                    "device_type_check": "Will verify device is Air-to-Water (DeviceType=1)",
                    "hot_water_state": f"Will {'enable' if enable else 'disable'} hot water boost",
                    "preserved_settings": "Temperature and power settings will be preserved",
                    "action": f"Hot water boost will be {'enabled' if enable else 'disabled'}"
                }
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Debug command failed: {str(e)}"
        }

async def debug_holiday_mode_command(email: str, password: str, device_id: int, enable: bool):
    """Debug function to show what holiday mode command would be sent (no actual command sent)"""
    try:
        api = MELCloudAPI(email=email, password=password)
        
        async with aiohttp.ClientSession() as session:
            # Login
            login_result = await api.login(session)
            if not login_result["success"]:
                return {
                    "success": False,
                    "error": f"Authentication failed: {login_result.get('error')}"
                }
            
            # Get the device state from MELCloud
            device_state_result = await api.get_device_state(session, device_id, bypass_rate_limit=True)
            if not device_state_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to get device state: {device_state_result.get('error')}",
                    "debug_info": device_state_result.get('debug_available_devices'),
                    "total_devices": device_state_result.get('total_devices')
                }
            
            # Get device data
            device_data = device_state_result.get("device_data")
            current_data = device_data.get("current_data", {})
            
            # Show current state
            current_holiday_mode = current_data.get("holiday_mode", False)
            
            # Build the command that would be sent
            new_state = {
                "DeviceID": device_data.get("device_id"),
                "DeviceType": device_data.get("device_type", 1),
                "HolidayMode": enable,
                "EffectiveFlags": 0x40,
                "HasPendingCommand": True,
                # Copy other required fields if they exist
                "Power": current_data.get("power", True),
                # Preserve all temperature settings
                "SetTemperatureZone1": current_data.get("set_temperature"),
                "SetTemperatureZone2": current_data.get("set_temperature_zone2"),
                "SetTankWaterTemperature": current_data.get("set_tank_temperature"),
                # Preserve operation mode settings
                "OperationMode": current_data.get("operation_mode"),
                "OperationModeZone1": current_data.get("operation_mode_zone1"),
                "OperationModeZone2": current_data.get("operation_mode_zone2"),
                # Preserve other mode settings
                "EcoHotWater": current_data.get("eco_hot_water", False),
                "ForcedHotWaterMode": current_data.get("forced_hot_water", False)
            }
            
            return {
                "success": True,
                "current_device_state": {
                    "device_id": device_data.get("device_id"),
                    "device_name": device_data.get("device_name"),
                    "current_holiday_mode": current_holiday_mode,
                    "current_temperature": current_data.get("set_temperature"),
                    "current_power": current_data.get("power")
                },
                "proposed_changes": {
                    "HolidayMode": f"{current_holiday_mode} → {enable}",
                    "DeviceID": device_data.get("device_id"),
                    "DeviceType": device_data.get("device_type", 1),
                    "EffectiveFlags": "0x40 (holiday mode flag)",
                    "HasPendingCommand": "True (will be set)"
                },
                "safety_checks": {
                    "device_type_check": "Will verify device is Air-to-Water (DeviceType=1)",
                    "holiday_mode_state": f"Will {'enable' if enable else 'disable'} holiday mode",
                    "preserved_settings": "Temperature and power settings will be preserved",
                    "action": f"Holiday mode will be {'enabled' if enable else 'disabled'}"
                }
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Debug command failed: {str(e)}"
        }

def auto_fetch_data():
    """Background function to automatically fetch and store MELCloud data with retry and recovery"""
    global cached_data, last_update, api_instance, db_error_count, last_db_error_time, startup_bypass_rate_limit
    
    logging.info("Auto-fetch: Starting data collection cycle")
    
    # Check disk space before proceeding
    try:
        with app.app_context():
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'melcloud.db')
            disk_info = get_disk_space(os.path.dirname(db_path))
            if 'error' not in disk_info and disk_info.get('available_mb', 0) < 100:
                logging.warning(f"Auto-fetch: Low disk space ({disk_info['available_mb']} MB available)")
                return
    except Exception as e:
        logging.warning(f"Auto-fetch: Could not check disk space: {str(e)}")
    
    # First, check rate limiting BEFORE doing any database operations
    if api_instance:
        current_time = time.time()
        elapsed = current_time - api_instance.last_request_time
        can_request = api_instance.can_make_request()
        
        logging.info(f"Auto-fetch: Rate limit check - Current time: {current_time:.2f}, Last request: {api_instance.last_request_time:.2f}, Elapsed: {elapsed:.2f}s, Can request: {can_request}")
        
        if not can_request and not startup_bypass_rate_limit:
            logging.info(f"Auto-fetch: Rate limited, waiting {api_instance.time_until_next_request()} seconds")
            return
        elif startup_bypass_rate_limit:
            logging.info("Auto-fetch: Bypassing rate limiting for startup call")
            startup_bypass_rate_limit = False  # Only bypass once
    else:
        logging.info("Auto-fetch: No existing API instance, will create new one")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            with app.app_context():
                # Check database health before attempting operations
                db_health = check_database_integrity()
                if not db_health['healthy']:
                    logging.warning(f"Auto-fetch: Database unhealthy: {db_health.get('error', 'Unknown issue')}")
                    
                    # Attempt recovery if it's a recoverable error
                    if db_health.get('readonly') or db_health.get('locked'):
                        logging.info("Auto-fetch: Attempting database recovery")
                        recovery_result = recover_database()
                        if recovery_result['success']:
                            logging.info(f"Auto-fetch: Database recovered successfully: {recovery_result.get('action', 'unknown')}")
                            # Reset error count after successful recovery
                            db_error_count = 0
                        else:
                            logging.error(f"Auto-fetch: Database recovery failed: {recovery_result.get('error')}")
                            record_database_error()
                            return
                    else:
                        record_database_error()
                        return
                
                # Use raw SQL to completely avoid SQLAlchemy session binding issues
                from sqlalchemy import text
                result = db.session.execute(text("SELECT id, email, password_encrypted, password_plain FROM users LIMIT 1")).fetchone()
                
                if not result:
                    logging.warning("Auto-fetch: No user credentials found, skipping data collection")
                    return
                
                # Extract values from raw SQL result
                user_id = result[0]
                user_email = result[1] 
                user_password = None
                try:
                    enc = result[2]
                    if enc:
                        user_password = decrypt_password(enc)
                except Exception:
                    user_password = None
                # Fallback only if legacy plaintext is present and non-empty
                if not user_password and result[3]:
                    user_password = result[3]
                if not user_password:
                    logging.warning("Auto-fetch: No valid MELCloud credentials available (encrypted or plaintext)")
                    return
                
                # Fetch data from MELCloud
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                result = loop.run_until_complete(
                    get_melcloud_data(email=user_email, password=user_password)
                )
                loop.close()
                
                if result["success"]:
                    # Update global cached data and API instance
                    cached_data = result
                    last_update = time.time()
                    api_instance = result.get("api_instance")
                    
                    # Update user name from MELCloud if available and not already set
                    user_info = result.get('login_result', {}).get('user_info', {})
                    user_name = user_info.get('name')
                    if user_name:
                        try:
                            # Update user name in database if not already set
                            db.session.execute(text("UPDATE users SET name = :name WHERE id = :user_id AND (name IS NULL OR name = '')"), 
                                             {'name': user_name, 'user_id': user_id})
                            db.session.commit()
                            logging.info(f"Auto-fetch: Updated user name to '{user_name}'")
                        except Exception as e:
                            logging.warning(f"Auto-fetch: Could not update user name: {e}")
                    
                    # Store device data to database with retry logic
                    devices = result.get('device_result', {}).get('devices', [])
                    stored_count = 0
                    
                    for device in devices:
                        def store_operation():
                            return store_device_data(user_id, device)
                        
                        retry_database_operation(store_operation)
                        stored_count += 1
                    
                    # Reset error count after successful operation
                    db_error_count = 0
                    logging.info(f"Auto-fetch: Successfully stored {stored_count} device(s)")
                    return  # Success - exit retry loop
                    
                else:
                    logging.error(f"Auto-fetch: Failed to fetch data - {result.get('error', 'Unknown error')}")
                    return  # API error, don't retry database operations
                
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Auto-fetch: Exception occurred (attempt {attempt + 1}/{max_retries}) - {error_msg}")
            
            # Check if this is a recoverable database error
            if is_database_error_recoverable(error_msg):
                record_database_error()
                
                # Try database recovery on the last attempt
                if attempt == max_retries - 1:
                    try:
                        with app.app_context():
                            logging.info("Auto-fetch: Final attempt - trying database recovery")
                            recovery_result = recover_database()
                            if recovery_result['success']:
                                logging.info(f"Auto-fetch: Recovery successful: {recovery_result.get('action')}")
                                # Reset error count after successful recovery
                                db_error_count = 0
                                return
                            else:
                                logging.error(f"Auto-fetch: Recovery failed: {recovery_result.get('error')}")
                    except Exception as recovery_error:
                        logging.error(f"Auto-fetch: Recovery attempt failed: {str(recovery_error)}")
                
                # Wait before retry (exponential backoff)
                wait_time = min(2 ** attempt, 30)  # Max 30 seconds
                if attempt < max_retries - 1:
                    logging.info(f"Auto-fetch: Waiting {wait_time} seconds before retry")
                    time.sleep(wait_time)
                    continue
            else:
                # Non-recoverable error, don't retry
                logging.error(f"Auto-fetch: Non-recoverable error: {error_msg}")
                return
    
    # If we get here, all retries failed
    logging.error("Auto-fetch: All retry attempts failed")
    check_service_restart_threshold()


def record_database_error():
    """Record a database error for tracking service restart threshold"""
    global db_error_count, last_db_error_time
    
    current_time = time.time()
    # Reset count if last error was more than 1 hour ago
    if current_time - last_db_error_time > 3600:
        db_error_count = 1
    else:
        db_error_count += 1
    
    last_db_error_time = current_time
    logging.warning(f"Database error recorded. Count: {db_error_count}/{max_db_errors}")
    

def check_service_restart_threshold():
    """Check if we should attempt service restart due to persistent errors"""
    global db_error_count, service_restart_count
    
    if db_error_count >= max_db_errors:
        service_restart_count += 1
        logging.error(f"Service restart threshold reached. Restart count: {service_restart_count}")
        
        # Attempt to restart auto-fetch service
        try:
            stop_auto_fetch()
            time.sleep(5)  # Wait before restart
            start_auto_fetch()
            
            logging.info("Auto-fetch service restarted successfully")
            # Reset error count after restart
            db_error_count = 0
            
        except Exception as e:
            logging.error(f"Failed to restart auto-fetch service: {str(e)}")


def retry_database_operation(operation, max_retries=3):
    """Retry database operations with exponential backoff"""
    for attempt in range(max_retries):
        try:
            return operation()
        except Exception as e:
            error_msg = str(e)
            logging.warning(f"Database operation failed (attempt {attempt + 1}/{max_retries}): {error_msg}")
            
            if is_database_error_recoverable(error_msg) and attempt < max_retries - 1:
                # Try recovery before next attempt
                try:
                    recovery_result = recover_database()
                    if recovery_result['success']:
                        logging.info(f"Database recovered before retry: {recovery_result.get('action')}")
                    else:
                        logging.warning(f"Database recovery failed: {recovery_result.get('error')}")
                except Exception as recovery_error:
                    logging.warning(f"Recovery attempt failed: {str(recovery_error)}")
                
                # Wait before retry
                wait_time = min(2 ** attempt, 10)
                time.sleep(wait_time)
                continue
            else:
                # Non-recoverable or final attempt
                raise e
    
    raise Exception(f"Database operation failed after {max_retries} attempts")


def start_auto_fetch(force_new=False):
    """Start the background auto-fetch thread"""
    global auto_fetch_thread, auto_fetch_enabled
    
    def auto_fetch_loop():
        """Main loop for auto-fetching data"""
        logging.info("Auto-fetch: Background thread started")
        
        # Check if we have any database data, if not, start immediately
        with app.app_context():
            try:
                from sqlalchemy import text
                result = db.session.execute(text("SELECT COUNT(*) FROM device_data")).fetchone()
                has_data = result[0] > 0 if result else False
                
                if has_data:
                    # Wait for small delay if we have existing data
                    startup_delay = 5  # Reduced from 15 seconds
                    logging.info(f"Auto-fetch: Database has data, waiting {startup_delay} seconds before starting data collection")
                    time.sleep(startup_delay)
                else:
                    # No data in database, start immediately
                    logging.info("Auto-fetch: No database data found, starting data collection immediately")
            except Exception as e:
                logging.warning(f"Auto-fetch: Could not check database status: {e}, using default startup delay")
                startup_delay = 5  # Reduced default delay
                time.sleep(startup_delay)
        
        while auto_fetch_enabled:
            # Check if API is enabled and get interval from database
            try:
                with app.app_context():
                    from database import get_fetch_interval_seconds, is_api_enabled
                    
                    if not is_api_enabled():
                        logging.info("Auto-fetch: API communications disabled, pausing data collection")
                        time.sleep(60)  # Check again in 1 minute
                        continue
                    
                    fetch_interval = get_fetch_interval_seconds()
                    if fetch_interval is None:
                        fetch_interval = 600  # Default to 10 minutes if not set
                        
            except Exception as e:
                logging.error(f"Auto-fetch: Error getting settings from database: {e}")
                fetch_interval = 600  # Fallback to 10 minutes
            
            try:
                auto_fetch_data()
            except Exception as e:
                logging.error(f"Auto-fetch: Loop exception - {str(e)}")
            
            # Wait for the configured interval, but check enabled flag periodically
            logging.info(f"Auto-fetch: Waiting {fetch_interval} seconds until next cycle")
            
            # Sleep in shorter intervals so we can respond to stop signals
            sleep_chunk = 10  # Check every 10 seconds
            total_slept = 0
            
            while total_slept < fetch_interval and auto_fetch_enabled:
                remaining = fetch_interval - total_slept
                sleep_time = min(sleep_chunk, remaining)
                time.sleep(sleep_time)
                total_slept += sleep_time
        
        logging.info("Auto-fetch: Background thread stopped")
    
    if force_new or auto_fetch_thread is None or not auto_fetch_thread.is_alive():
        auto_fetch_enabled = True  # Ensure enabled flag is set
        auto_fetch_thread = threading.Thread(target=auto_fetch_loop, daemon=True)
        auto_fetch_thread.start()
        logging.info("Auto-fetch: Started background data collection thread")
    else:
        logging.warning("Auto-fetch: Thread is already running, not starting new one")


def stop_auto_fetch():
    """Stop the background auto-fetch thread"""
    global auto_fetch_enabled, auto_fetch_thread
    auto_fetch_enabled = False
    logging.info("Auto-fetch: Stopping background thread")
    
    # Wait for thread to actually stop
    if auto_fetch_thread and auto_fetch_thread.is_alive():
        logging.info("Auto-fetch: Waiting for thread to stop...")
        auto_fetch_thread.join(timeout=15)  # Wait up to 15 seconds (should be much faster now)
        if auto_fetch_thread.is_alive():
            logging.warning("Auto-fetch: Thread did not stop within timeout")
        else:
            logging.info("Auto-fetch: Thread stopped successfully")


# ============================================================================
# Authentication Routes
# ============================================================================

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup page to create first admin user"""
    # If admin already exists, redirect to login
    if has_admin_user():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            data = request.get_json() or request.form.to_dict()
            
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            confirm_password = data.get('confirm_password', '')
            timezone = data.get('timezone', 'UTC').strip()
            csrf_token = data.get('csrf_token', '')
            
            # Validate CSRF token
            if not validate_csrf_token(csrf_token):
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 400
                flash('Security error. Please try again.', 'error')
                return render_template('setup.html', csrf_token=generate_csrf_token())
            
            # Validate required fields
            if not all([username, email, password]):
                error = 'All fields are required'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return render_template('setup.html', csrf_token=generate_csrf_token())
            
            # Validate password match
            if password != confirm_password:
                error = 'Passwords do not match'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return render_template('setup.html', csrf_token=generate_csrf_token())
            
            # Validate password strength
            password_errors = validate_password_strength(password)
            if password_errors:
                error = '; '.join(password_errors)
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return render_template('setup.html', csrf_token=generate_csrf_token())
            
            # Check if username or email already exists
            if get_web_user_by_username(username):
                error = 'Username already exists'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return render_template('setup.html', csrf_token=generate_csrf_token())
            
            # Validate timezone
            if timezone not in get_common_timezones():
                error = 'Invalid timezone selected'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return render_template('setup.html', csrf_token=generate_csrf_token())
            
            # Create admin user
            admin_user = create_web_user(username, email, password, role='admin')
            
            # Create default device config with selected timezone
            # Use device_id=1 as default for first device
            try:
                create_device_config(device_id=1, timezone=timezone, device_name="Heat Pump")
                logging.info(f"Created device config for device 1 with timezone {timezone}")
            except Exception as e:
                logging.warning(f"Failed to create device config: {e}")
                # Continue with setup even if device config fails
            
            # Log security event
            log_security_event('ADMIN_CREATED', admin_user.id, details=f'Username: {username}, Timezone: {timezone}')
            
            if request.is_json:
                return jsonify({
                    'success': True, 
                    'message': 'Admin account created successfully',
                    'redirect': '/login'
                })
            else:
                flash('Admin account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
                
        except Exception as e:
            logging.error(f"Setup error: {e}")
            error = 'Failed to create admin account'
            if request.is_json:
                return jsonify({'success': False, 'error': error}), 500
            flash(error, 'error')
            return render_template('setup.html', csrf_token=generate_csrf_token())
    
    # GET request - show setup form
    return render_template('setup.html', csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If already authenticated, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Check if setup is needed
    if not has_admin_user():
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        try:
            data = request.get_json() or request.form.to_dict()
            
            username_or_email = data.get('username', '').strip()
            password = data.get('password', '')
            remember_me = data.get('remember_me', False)
            csrf_token = data.get('csrf_token', '')
            
            client_ip = get_client_ip()
            
            # Validate CSRF token
            if not validate_csrf_token(csrf_token):
                log_security_event('LOGIN_CSRF_FAIL', ip_address=client_ip)
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 400
                flash('Security error. Please try again.', 'error')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            # Check if IP is locked
            if is_ip_locked(client_ip):
                log_security_event('LOGIN_IP_LOCKED', ip_address=client_ip)
                error = 'Too many failed login attempts. Please try again later.'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 429
                flash(error, 'error')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            # Validate required fields
            if not username_or_email or not password:
                record_failed_login(client_ip)
                error = 'Username and password are required'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return render_template('login.html', csrf_token=generate_csrf_token())
            
            # Authenticate user
            user = authenticate_web_user(username_or_email, password)
            
            if user:
                # Successful login
                reset_login_attempts(client_ip)
                
                # Create secure session
                if create_secure_session(user, remember_me):
                    login_user(user, remember=remember_me)
                    
                    log_security_event('LOGIN_SUCCESS', user.id)
                    
                    if request.is_json:
                        return jsonify({
                            'success': True,
                            'message': 'Login successful',
                            'redirect': '/dashboard',
                            'user': user.to_dict()
                        })
                    else:
                        flash(f'Welcome back, {user.username}!', 'success')
                        return redirect(url_for('dashboard'))
                else:
                    error = 'Failed to create session'
                    if request.is_json:
                        return jsonify({'success': False, 'error': error}), 500
                    flash(error, 'error')
                    return render_template('login.html', csrf_token=generate_csrf_token())
            else:
                # Failed login
                record_failed_login(client_ip)
                log_security_event('LOGIN_FAIL', ip_address=client_ip, details=f'Username: {username_or_email}')
                
                error = 'Invalid username or password'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 401
                flash(error, 'error')
                return render_template('login.html', csrf_token=generate_csrf_token())
                
        except Exception as e:
            logging.error(f"Login error: {e}")
            record_failed_login(get_client_ip())
            error = 'Login failed due to server error'
            if request.is_json:
                return jsonify({'success': False, 'error': error}), 500
            flash(error, 'error')
            return render_template('login.html', csrf_token=generate_csrf_token())
    
    # GET request - show login form
    return render_template('login.html', csrf_token=generate_csrf_token())

@app.route('/logout')
@flask_login_required
def logout():
    """Logout route"""
    try:
        user_id = current_user.id
        destroy_session()
        logout_user()
        
        log_security_event('LOGOUT_SUCCESS', user_id)
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Logged out successfully', 'redirect': '/login'})
        else:
            flash('You have been logged out successfully.', 'info')
            return redirect(url_for('login'))
            
    except Exception as e:
        logging.error(f"Logout error: {e}")
        if request.is_json:
            return jsonify({'success': False, 'error': 'Logout failed'}), 500
        flash('Logout failed', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
@require_setup()
@login_required
def dashboard():
    """Protected dashboard route - serves the main MELCloud interface"""
    return render_template('index.html')


@app.route('/energy')
@require_setup()
@login_required
def energy():
    """Energy page with COP and SCOP statistics"""
    return render_template('energy.html')

@app.route('/schedules')
@require_setup()
@admin_required
def schedules():
    """Schedules page for managing device automation (admin only)"""
    return render_template('schedules.html')

@app.route('/data-history')
@require_setup()
@login_required
def data_history():
    """Data History page showing historical device data"""
    return render_template('data-history.html')

@app.route('/api/energy-stats')
@require_setup()
@flask_login_required
def get_energy_stats():
    """API endpoint to get energy statistics (COP and SCOP)"""
    try:
        # Get current user from Flask-Login
        if not current_user.is_authenticated:
            return jsonify({'error': 'User not authenticated'}), 401
        # Determine which MELCloud device owner the data belongs to
        device_owner = get_user()
        if not device_owner:
            return jsonify({'error': 'Device data not configured'}), 404

        owner_id = device_owner.id

        # ETag built from last update, device owner and requester id to keep caches isolated per web user
        global last_update
        etag = _build_etag('energy_stats', current_user.id, owner_id, int(last_update or 0))
        if _is_not_modified(etag):
            resp = app.response_class(status=304)
            _apply_cache_headers(resp, etag)
            return resp
        
        # Get latest device data (same approach as original dashboard)
        devices = get_latest_devices_for_dashboard(owner_id)
        
        if not devices or len(devices) == 0:
            return jsonify({
                'yesterday': {'cop': 0, 'details': 'No devices found'},
                'month': {'cop': 0, 'details': 'No devices found'}, 
                'year': {'cop': 0, 'details': 'No devices found'}
            })
        
        # Use first device data (same as original dashboard)
        device = devices[0]
        device_data = device.get('current_data', {})
        
        from datetime import datetime, timedelta
        
        # Calculate date ranges
        # Note: MELCloud API always provides yesterday's daily energy totals in today's responses
        # So to get "yesterday's" energy data, we need to query today's records
        today = datetime.now()
        yesterday = today - timedelta(days=1)
        thirty_days_ago = today - timedelta(days=30)
        twelve_months_ago = today - timedelta(days=365)
        
        # Get yesterday's energy data directly from today's records (no calculations needed)
        # MELCloud sends yesterday's daily totals in today's responses - just grab them directly
        logging.info(f"Getting yesterday's data from today's records")
        yesterday_data = get_daily_energy_from_today(owner_id)
        
        logging.info(f"Querying month: {thirty_days_ago} to {today}")
        month_data = get_historical_cop_with_totals(owner_id, thirty_days_ago, today + timedelta(days=1))
        
        logging.info(f"Querying year: {twelve_months_ago} to {today}")
        year_data = get_historical_cop_with_totals(owner_id, twelve_months_ago, today + timedelta(days=1))
        
        yesterday_cop = yesterday_data['cop']
        month_cop = month_data['cop'] 
        year_scop = year_data['cop']
        
        # Get current day's COP for fallback
        current_cop = calculate_current_cop(device_data)
        
        logging.info(f"COP Results - Yesterday: {yesterday_cop}, Month: {month_cop}, Year: {year_scop}, Current: {current_cop}")
        
        # Only fallback to current day's COP if absolutely no historical data exists
        # This allows calculations based on whatever data is available (even if less than full period)
        if yesterday_cop == 0:
            logging.info("No yesterday data found, using current COP as fallback")
            yesterday_cop = current_cop
        
        # Get data counts for each period (yesterday data comes from today's records)
        yesterday_days = 1  # We got yesterday's data from today's record
        month_days = get_historical_cop_days(owner_id, thirty_days_ago, today + timedelta(days=1))
        year_days = get_historical_cop_days(owner_id, twelve_months_ago, today + timedelta(days=1))
        
        # Add debug info to response for troubleshooting
        debug_info = {
            'device_keys': list(device.keys()),
            'current_data_keys': list(device_data.keys()),
            'sample_fields': {k: v for k, v in device_data.items() if 'energy' in k.lower() or 'cop' in k.lower() or k in ['total_energy_consumed', 'total_energy_produced']},
            'current_cop': current_cop,
            'historical_cops': {
                'yesterday': yesterday_cop,
                'month': month_cop, 
                'year': year_scop
            },
            'data_days': {
                'yesterday': yesterday_days,
                'month': month_days,
                'year': year_days
            }
        }
        
        resp = jsonify({
            'yesterday': {
                'cop': yesterday_cop,
                'consumed': yesterday_data['consumed'],
                'produced': yesterday_data['produced'],
                'days': yesterday_data['days'],
                'details': f'Consumed: {yesterday_data["consumed"]:.1f} kWh, Produced: {yesterday_data["produced"]:.1f} kWh' if yesterday_cop > 0 else 'No yesterday data available'
            },
            'month': {
                'cop': month_cop,
                'consumed': month_data['consumed'],
                'produced': month_data['produced'], 
                'days': month_data['days'],
                'details': f'Consumed: {month_data["consumed"]:.1f} kWh, Produced: {month_data["produced"]:.1f} kWh ({month_data["days"]} days)' if month_cop > 0 else 'No monthly data available'
            },
            'year': {
                'cop': year_scop,
                'consumed': year_data['consumed'],
                'produced': year_data['produced'],
                'days': year_data['days'], 
                'details': f'Consumed: {year_data["consumed"]:.1f} kWh, Produced: {year_data["produced"]:.1f} kWh ({year_data["days"]} days)' if year_scop > 0 else 'No yearly data available'
            },
            'debug': debug_info
        })
        _apply_cache_headers(resp, etag)
        return resp
        
    except Exception as e:
        logging.error(f"Error getting energy stats: {e}")
        return jsonify({'error': str(e)}), 500


def calculate_current_cop(device_data):
    """Calculate current COP using MELCloud data structure"""
    try:
        # First, check if there's already a calculated COP
        daily_cop = device_data.get('daily_cop')
        if daily_cop and daily_cop > 0:
            logging.info(f"Using existing daily_cop: {daily_cop}")
            return daily_cop
        
        # If not, try to calculate from energy data (which are objects)
        daily_energy_consumed = device_data.get('daily_energy_consumed', {})
        daily_energy_produced = device_data.get('daily_energy_produced', {})
        
        logging.info(f"Energy consumed object: {daily_energy_consumed}")
        logging.info(f"Energy produced object: {daily_energy_produced}")
        
        # Try to find total values in the energy objects
        if isinstance(daily_energy_consumed, dict) and isinstance(daily_energy_produced, dict):
            # Look for common field names in energy objects
            consumed_fields = ['total', 'heating', 'hot_water', 'value']
            produced_fields = ['total', 'heating', 'hot_water', 'value']
            
            total_consumed = 0
            total_produced = 0
            
            # Sum up all energy consumption values
            for field in consumed_fields:
                if field in daily_energy_consumed and daily_energy_consumed[field]:
                    total_consumed += float(daily_energy_consumed[field])
            
            # Sum up all energy production values  
            for field in produced_fields:
                if field in daily_energy_produced and daily_energy_produced[field]:
                    total_produced += float(daily_energy_produced[field])
            
            logging.info(f"Total consumed: {total_consumed}, Total produced: {total_produced}")
            
            if total_consumed > 0 and total_produced > 0:
                cop = total_produced / total_consumed
                cop = min(max(cop, 1.0), 8.0)
                logging.info(f"Calculated COP from energy objects: {cop}")
                return cop
        
        logging.info("No valid COP or energy data found")
        return 0
        
    except Exception as e:
        logging.error(f"Error calculating current COP: {e}")
        return 0

def get_historical_cop(user_id, date_from, date_to):
    """Calculate COP from total energy produced/consumed for a date range"""
    try:
        from database import DeviceData
        from datetime import datetime
        import json
        
        # Query database for device data in the date range
        query = DeviceData.query.filter_by(user_id=user_id)
        query = query.filter(DeviceData.timestamp >= date_from)
        query = query.filter(DeviceData.timestamp <= date_to)
        query = query.order_by(DeviceData.timestamp.desc())
        
        records = query.all()
        
        logging.info(f"Found {len(records)} total records for {date_from} to {date_to}")
        
        if not records:
            logging.info(f"No historical data found for {date_from} to {date_to}")
            return 0
        
        # Sum up all energy produced and consumed for the entire period
        # Use a dictionary to track unique dates and avoid double-counting
        daily_energy_data = {}  # date -> {consumed, produced}
        
        for record in records:
            try:
                # Parse the device data JSON
                device_data = record.device_data if hasattr(record, 'device_data') else {}
                if isinstance(device_data, str):
                    device_data = json.loads(device_data)
                
                # Look for energy data in current_data
                current_data = device_data.get('current_data', {})
                
                # Get the daily energy date to ensure uniqueness
                daily_energy_date = current_data.get('daily_energy_date')
                if not daily_energy_date:
                    continue
                
                # Convert to date string for grouping
                if isinstance(daily_energy_date, str):
                    date_key = daily_energy_date.split('T')[0]  # Extract just the date part
                else:
                    date_key = str(daily_energy_date).split(' ')[0]
                
                # Skip if we already have data for this date
                if date_key in daily_energy_data:
                    continue
                
                # Get energy objects
                daily_energy_consumed = current_data.get('daily_energy_consumed', {})
                daily_energy_produced = current_data.get('daily_energy_produced', {})
                
                # Extract energy values from objects
                consumed = extract_energy_total(daily_energy_consumed)
                produced = extract_energy_total(daily_energy_produced)
                
                if consumed > 0 and produced > 0:
                    daily_energy_data[date_key] = {
                        'consumed': consumed,
                        'produced': produced
                    }
                
            except Exception as e:
                logging.warning(f"Error parsing device data: {e}")
                continue
        
        # Sum up unique daily totals
        total_energy_produced = sum(day['produced'] for day in daily_energy_data.values())
        total_energy_consumed = sum(day['consumed'] for day in daily_energy_data.values())
        valid_days = len(daily_energy_data)
        
        logging.info(f"Processed dates: {list(daily_energy_data.keys())}")
        logging.info(f"Energy totals - Consumed: {total_energy_consumed}, Produced: {total_energy_produced}")
        
        if total_energy_consumed > 0 and total_energy_produced > 0:
            # Calculate COP as total produced / total consumed for entire period
            cop = total_energy_produced / total_energy_consumed
            logging.info(f"Historical COP for {date_from} to {date_to}: {cop:.2f} (from {valid_days} unique days, {total_energy_produced:.2f} produced / {total_energy_consumed:.2f} consumed)")
            return cop
        
        logging.info(f"No valid energy data found in {len(records)} records ({valid_days} unique days)")
        return 0
        
    except Exception as e:
        logging.error(f"Error getting historical COP: {e}")
        return 0

def extract_energy_total(energy_object):
    """Extract total energy value from energy object"""
    try:
        if not isinstance(energy_object, dict):
            return 0
        
        # Look for common field names and sum them
        total = 0
        energy_fields = ['total', 'heating', 'hot_water', 'value', 'cooling']
        
        for field in energy_fields:
            if field in energy_object and energy_object[field]:
                total += float(energy_object[field])
        
        return total
        
    except Exception as e:
        logging.warning(f"Error extracting energy total: {e}")
        return 0

def get_daily_energy_from_today(user_id):
    """Get yesterday's daily energy data directly from today's database records"""
    try:
        from database import DeviceData
        from datetime import datetime
        
        today = datetime.now()
        logging.info(f"Getting daily energy from today's records for user {user_id}")
        
        # Get the most recent record from today
        query = DeviceData.query.filter_by(user_id=user_id)
        query = query.filter(DeviceData.timestamp >= today.replace(hour=0, minute=0, second=0, microsecond=0))
        query = query.order_by(DeviceData.timestamp.desc())
        
        record = query.first()
        
        if not record:
            logging.info("No records found for today, returning zeros")
            return {'cop': 0, 'consumed': 0, 'produced': 0, 'days': 0}
        
        # Extract daily energy values directly from the database fields
        total_consumed = (
            (record.daily_heating_energy_consumed or 0) +
            (record.daily_cooling_energy_consumed or 0) +
            (record.daily_hot_water_energy_consumed or 0)
        )
        
        total_produced = (
            (record.daily_heating_energy_produced or 0) +
            (record.daily_cooling_energy_produced or 0) +
            (record.daily_hot_water_energy_produced or 0)
        )
        
        logging.info(f"Daily energy from today's record: consumed={total_consumed}, produced={total_produced}")
        
        # Calculate COP if we have valid data
        if total_consumed > 0 and total_produced > 0:
            cop = total_produced / total_consumed
            logging.info(f"Calculated COP: {cop}")
            return {
                'cop': cop,
                'consumed': total_consumed,
                'produced': total_produced,
                'days': 1
            }
        
        logging.info("No valid energy data, returning zeros")
        return {'cop': 0, 'consumed': 0, 'produced': 0, 'days': 0}
        
    except Exception as e:
        logging.error(f"Error getting daily energy from today: {e}")
        return {'cop': 0, 'consumed': 0, 'produced': 0, 'days': 0}

def get_historical_cop_with_totals(user_id, date_from, date_to):
    """Calculate COP and return energy totals for a date range"""
    try:
        from database import DeviceData
        from datetime import datetime
        
        logging.info(f"COP calculation for user {user_id}, date range: {date_from} to {date_to}")
        
        # Query database for device data in the date range
        query = DeviceData.query.filter_by(user_id=user_id)
        query = query.filter(DeviceData.timestamp >= date_from)
        query = query.filter(DeviceData.timestamp <= date_to)
        query = query.order_by(DeviceData.timestamp.desc())
        
        records = query.all()
        logging.info(f"Found {len(records)} records in date range")
        
        if not records:
            logging.info("No records found, returning zeros")
            return {'cop': 0, 'consumed': 0, 'produced': 0, 'days': 0}
        
        # Sum up all energy produced and consumed for the entire period
        # Use a dictionary to track unique dates and avoid double-counting
        daily_energy_data = {}  # date -> {consumed, produced}
        
        for record in records:
            try:
                # Get the daily energy date to ensure uniqueness
                daily_energy_date = record.daily_energy_date
                if not daily_energy_date:
                    continue
                
                # Convert to date string for grouping
                if isinstance(daily_energy_date, str):
                    date_key = daily_energy_date.split('T')[0]  # Extract just the date part
                else:
                    date_key = str(daily_energy_date).split(' ')[0]
                
                # Skip if we already have data for this date
                if date_key in daily_energy_data:
                    continue
                
                # Sum all the energy categories from database columns
                total_consumed = (
                    (record.daily_heating_energy_consumed or 0) +
                    (record.daily_cooling_energy_consumed or 0) +
                    (record.daily_hot_water_energy_consumed or 0)
                )
                
                total_produced = (
                    (record.daily_heating_energy_produced or 0) +
                    (record.daily_cooling_energy_produced or 0) +
                    (record.daily_hot_water_energy_produced or 0)
                )
                
                if total_consumed > 0 and total_produced > 0:
                    daily_energy_data[date_key] = {
                        'consumed': total_consumed,
                        'produced': total_produced
                    }
                    logging.info(f"Added energy data for {date_key}: consumed={total_consumed}, produced={total_produced}")
                
            except Exception as e:
                logging.warning(f"Error parsing device data: {e}")
                continue
        
        # Sum up unique daily totals
        total_energy_produced = sum(day['produced'] for day in daily_energy_data.values())
        total_energy_consumed = sum(day['consumed'] for day in daily_energy_data.values())
        valid_days = len(daily_energy_data)
        
        logging.info(f"Daily energy data collected: {len(daily_energy_data)} unique days")
        logging.info(f"Total produced: {total_energy_produced}, consumed: {total_energy_consumed}")
        
        if total_energy_consumed > 0 and total_energy_produced > 0:
            # Calculate COP as total produced / total consumed for entire period
            cop = total_energy_produced / total_energy_consumed
            logging.info(f"Calculated COP: {cop}")
            return {
                'cop': cop,
                'consumed': total_energy_consumed,
                'produced': total_energy_produced,
                'days': valid_days
            }
        
        logging.info("Insufficient energy data, returning zeros")
        return {'cop': 0, 'consumed': 0, 'produced': 0, 'days': 0}
        
    except Exception as e:
        logging.error(f"Error getting historical COP with totals: {e}")
        return {'cop': 0, 'consumed': 0, 'produced': 0, 'days': 0}

def get_historical_cop_days(user_id, date_from, date_to):
    """Get count of days with energy data for a date range"""
    try:
        from database import DeviceData
        import json
        
        query = DeviceData.query.filter_by(user_id=user_id)
        query = query.filter(DeviceData.timestamp >= date_from)
        query = query.filter(DeviceData.timestamp <= date_to)
        
        records = query.all()
        daily_energy_data = {}
        
        for record in records:
            try:
                device_data = record.device_data if hasattr(record, 'device_data') else {}
                if isinstance(device_data, str):
                    device_data = json.loads(device_data)
                
                current_data = device_data.get('current_data', {})
                daily_energy_date = current_data.get('daily_energy_date')
                
                if not daily_energy_date:
                    continue
                
                date_key = daily_energy_date.split('T')[0] if isinstance(daily_energy_date, str) else str(daily_energy_date).split(' ')[0]
                
                if date_key in daily_energy_data:
                    continue
                
                daily_energy_consumed = current_data.get('daily_energy_consumed', {})
                daily_energy_produced = current_data.get('daily_energy_produced', {})
                
                consumed = extract_energy_total(daily_energy_consumed)
                produced = extract_energy_total(daily_energy_produced)
                
                if consumed > 0 and produced > 0:
                    daily_energy_data[date_key] = True
                    
            except Exception:
                continue
        
        return len(daily_energy_data)
        
    except Exception as e:
        logging.error(f"Error counting energy days: {e}")
        return 0


# ============================================================================
# Device Control API Endpoints - MELCloud Integration
# ============================================================================




@app.route('/api/device/<int:device_id>/temperature', methods=['POST'])
@require_setup()
@login_required
def set_device_temperature(device_id):
    """Set device temperature using MELCloud API"""
    try:
        data = request.get_json()
        temperature = data.get('temperature')
        bypass_rate_limit = data.get('bypass_rate_limit', False)  # Allow bypass for test-controls
        
        # Debug logging to confirm endpoint is being called
        app.logger.info(f"Temperature change request received: device_id={device_id}, temperature={temperature}, bypass_rate_limit={bypass_rate_limit}")
        
        if not temperature or not isinstance(temperature, (int, float)):
            app.logger.error(f"Invalid temperature value received: {temperature}")
            return jsonify({'error': 'Invalid temperature value'}), 400
            
        if temperature < 10 or temperature > 30:
            app.logger.error(f"Temperature out of range: {temperature}°C (must be 10-30°C)")
            return jsonify({'error': 'Temperature must be between 10-30°C'}), 400
        
        # Get user credentials from database
        user = get_user()
        user_pwd = get_decrypted_melcloud_password(user) if user else None
        if not user or not user.email or not user_pwd:
            app.logger.error("MELCloud credentials not configured for temperature change")
            return jsonify({'error': 'MELCloud credentials not configured'}), 400
        
        app.logger.info(f"Executing temperature command via MELCloud API for device {device_id}")
        
        # Execute MELCloud API command with optional bypass
        result = asyncio.run(execute_temperature_command(user.email, user_pwd, device_id, temperature, bypass_rate_limit))
        
        if result['success']:
            app.logger.info(f"Successfully set device {device_id} temperature to {temperature}°C")
            return jsonify({
                'success': True,
                'message': f'Temperature set to {temperature}°C',
                'device_id': device_id,
                'temperature': temperature,
                'api_response': result.get('response')
            })
        else:
            app.logger.error(f"Failed to set temperature: {result.get('error')}")
            return jsonify({'error': result.get('error', 'Failed to set temperature')}), 500
        
    except Exception as e:
        app.logger.error(f"Error setting temperature: {e}")
        return jsonify({'error': 'Failed to set temperature'}), 500

@app.route('/api/device/<int:device_id>/hot-water', methods=['POST'])
@require_setup()
@login_required
def control_hot_water(device_id):
    """Control hot water boost mode using MELCloud API"""
    try:
        data = request.get_json()
        enable = data.get('enable')
        bypass_rate_limit = data.get('bypass_rate_limit', False)  # Allow bypass for test-controls
        
        if enable is None or not isinstance(enable, bool):
            return jsonify({'error': 'Invalid enable value'}), 400
        
        # Get user credentials from database
        user = get_user()
        user_pwd = get_decrypted_melcloud_password(user) if user else None
        if not user or not user.email or not user_pwd:
            return jsonify({'error': 'MELCloud credentials not configured'}), 400
            
        # Execute MELCloud API command with optional bypass
        result = asyncio.run(execute_hot_water_command(user.email, user_pwd, device_id, enable, bypass_rate_limit))
        
        if result['success']:
            action = 'enabled' if enable else 'disabled'
            app.logger.info(f"Successfully set device {device_id} hot water boost to {action}")
            return jsonify({
                'success': True,
                'message': f'Hot water boost {action}',
                'device_id': device_id,
                'hot_water_enabled': enable,
                'api_response': result.get('response')
            })
        else:
            app.logger.error(f"Failed to control hot water: {result.get('error')}")
            return jsonify({'error': result.get('error', 'Failed to control hot water')}), 500
        
    except Exception as e:
        app.logger.error(f"Error controlling hot water: {e}")
        return jsonify({'error': 'Failed to control hot water'}), 500

@app.route('/api/device/<int:device_id>/holiday-mode', methods=['POST'])
@require_setup()
@login_required
def set_holiday_mode(device_id):
    """Enable/disable holiday mode using MELCloud API"""
    try:
        data = request.get_json()
        enable = data.get('enable')
        bypass_rate_limit = data.get('bypass_rate_limit', False)  # Allow bypass for test-controls
        
        if enable is None or not isinstance(enable, bool):
            return jsonify({'error': 'Invalid enable value'}), 400
        
        # Get user credentials from database
        user = get_user()
        user_pwd = get_decrypted_melcloud_password(user) if user else None
        if not user or not user.email or not user_pwd:
            return jsonify({'error': 'MELCloud credentials not configured'}), 400
            
        # Execute MELCloud API command with optional bypass
        result = asyncio.run(execute_holiday_mode_command(user.email, user_pwd, device_id, enable, bypass_rate_limit))
        
        if result['success']:
            action = 'enabled' if enable else 'disabled'
            app.logger.info(f"Successfully set device {device_id} holiday mode to {action}")
            return jsonify({
                'success': True,
                'message': f'Holiday mode {action}',
                'device_id': device_id,
                'holiday_mode_enabled': enable,
                'api_response': result.get('response')
            })
        else:
            app.logger.error(f"Failed to set holiday mode: {result.get('error')}")
            return jsonify({'error': result.get('error', 'Failed to set holiday mode')}), 500
        
    except Exception as e:
        app.logger.error(f"Error setting holiday mode: {e}")
        return jsonify({'error': 'Failed to set holiday mode'}), 500

@app.route('/settings')
@require_setup()
@login_required
def settings():
    """Settings page for user profile and admin functions"""
    from auth import generate_csrf_token
    return render_template(
        'settings.html',
        csrf_token=generate_csrf_token(),
        is_admin=current_user.is_admin(),
        current_username=getattr(current_user, 'username', None),
        current_email=getattr(current_user, 'email', None)
    )


# ============================================================================
# Help Page
# ============================================================================

@app.route('/help')
@require_setup()
@login_required
def help_page():
    """Help and documentation page"""
    return render_template('help.html')

# ============================================================================
# Security Status Endpoints
# ============================================================================

@app.route('/api/security/encryption-status')
@login_required
@admin_required
def encryption_status():
    """Report application encryption status without exposing secrets."""
    try:
        status = get_encryption_status()
        # Include simple metrics about user credentials encryption
        from database import User
        total = User.query.count()
        encrypted = User.query.filter(User.password_encrypted.isnot(None), User.password_encrypted != '').count()
        plaintext_nonempty = User.query.filter(User.password_plain.isnot(None), User.password_plain != '').count()
        status.update({
            'users_total': total,
            'users_encrypted': encrypted,
            'users_with_plaintext': plaintext_nonempty,
        })
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logging.error(f"Encryption status error: {e}")
        return jsonify({'success': False, 'error': 'Failed to get encryption status'}), 500

# ============================================================================
# API Settings Routes
# ============================================================================

@app.route('/api/settings/api', methods=['GET'])
@require_setup()
@login_required
def get_api_settings():
    """Get current API settings"""
    try:
        from database import get_api_settings
        settings = get_api_settings()
        return jsonify(settings.to_dict())
    except Exception as e:
        app.logger.error(f"Error getting API settings: {e}")
        return jsonify({'error': 'Failed to load API settings'}), 500

@app.route('/api/settings/api', methods=['POST'])
@require_setup()
@admin_required
def update_api_settings():
    """Update API settings (admin only)"""
    try:
        from auth import validate_csrf_token
        from database import update_api_settings
        
        # Validate CSRF token
        if not validate_csrf_token(request.get_json().get('csrf_token')):
            return jsonify({'error': 'Invalid CSRF token'}), 403
        
        data = request.get_json()
        fetch_interval = data.get('fetch_interval_minutes')
        api_enabled = data.get('api_enabled')
        
        # Validate fetch interval
        if fetch_interval is not None:
            try:
                fetch_interval = int(fetch_interval)
                if fetch_interval < 5:
                    return jsonify({'error': 'Fetch interval must be at least 5 minutes'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid fetch interval value'}), 400
        
        # Update settings
        settings = update_api_settings(
            fetch_interval_minutes=fetch_interval,
            api_enabled=api_enabled,
            user_id=current_user.id
        )
        
        app.logger.info(f"API settings updated by user {current_user.id}: interval={fetch_interval}min, enabled={api_enabled}")
        
        # Restart auto-fetch service to apply new settings immediately
        try:
            app.logger.info("Auto-fetch: Restarting service due to settings change")
            stop_auto_fetch()
            start_auto_fetch(force_new=True)  # Force creation of new thread
            service_restarted = True
            app.logger.info("Auto-fetch: Service restarted successfully")
        except Exception as restart_error:
            app.logger.error(f"Auto-fetch: Failed to restart service: {restart_error}")
            service_restarted = False
        
        response_data = settings.to_dict()
        response_data['service_restarted'] = service_restarted
        return jsonify(response_data)
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.error(f"Error updating API settings: {e}")
        return jsonify({'error': 'Failed to update API settings'}), 500

@app.route('/api/connection-status', methods=['GET'])
@require_setup()
@login_required
def connection_status():
    """Get real-time MELCloud API connection status"""
    global db_error_count, auto_fetch_enabled, auto_fetch_thread, api_instance
    
    try:
        from database import get_fetch_interval_seconds, is_api_enabled
        import time
        
        # Check API settings
        api_enabled = is_api_enabled()
        fetch_interval = get_fetch_interval_seconds()
        
        # Check auto-fetch service status
        service_running = auto_fetch_enabled and auto_fetch_thread and auto_fetch_thread.is_alive()
        
        # Get last API call time
        last_api_call = api_instance.last_request_time if api_instance else 0
        current_time = time.time()
        
        # Calculate countdown timer data
        expected_interval = fetch_interval if fetch_interval else 600
        time_since_call = current_time - last_api_call if last_api_call > 0 else None
        
        # Calculate next refresh time and countdown
        if last_api_call > 0:
            next_request_time = last_api_call + expected_interval
            countdown_seconds = max(0, int(next_request_time - current_time))
        else:
            next_request_time = current_time + expected_interval  # Estimate for startup
            countdown_seconds = expected_interval
        
        # Calculate progress percentage (0-100)
        if time_since_call is not None and expected_interval > 0:
            progress_percentage = min(100, (time_since_call / expected_interval) * 100)
        else:
            progress_percentage = 0
        
        # Calculate status based on multiple factors
        status_info = {
            'timestamp': current_time,
            'api_enabled': api_enabled,
            'service_running': service_running,
            'error_count': db_error_count,
            'fetch_interval_seconds': fetch_interval,
            'last_api_call': last_api_call,
            'next_request_time': next_request_time,
            'time_since_last_call': time_since_call,
            'countdown_seconds': countdown_seconds,
            'progress_percentage': progress_percentage
        }
        
        # Determine connection status
        if not api_enabled:
            color = 'gray'
            status = 'API Disabled'
            detail = 'MELCloud API communications are disabled in settings'
        elif not service_running:
            color = 'red'
            status = 'Service Stopped'
            detail = 'Auto-fetch service is not running'
        elif db_error_count >= 3:
            color = 'red'
            status = 'Multiple Failures'
            detail = f'{db_error_count} consecutive errors - service may restart'
        elif last_api_call == 0:
            color = 'gray'
            status = 'Starting Up'
            detail = 'Waiting for first API call'
        else:
            # Check timing based on configured interval
            time_since_call = current_time - last_api_call
            expected_interval = fetch_interval if fetch_interval else 600
            buffer_time = expected_interval * 0.25  # 25% buffer
            warning_time = expected_interval * 2    # 2x interval = warning
            
            if time_since_call <= expected_interval + buffer_time:
                if db_error_count == 0:
                    color = 'green'
                    status = 'Connected'
                    detail = f'Last update {int(time_since_call/60)} min ago'
                else:
                    color = 'amber'
                    status = 'Some Errors'
                    detail = f'{db_error_count} recent errors, last update {int(time_since_call/60)} min ago'
            elif time_since_call <= warning_time:
                color = 'amber'
                status = 'Running Late'
                detail = f'Expected update {int((time_since_call - expected_interval)/60)} min ago'
            else:
                color = 'red'
                status = 'Overdue'
                detail = f'Last update {int(time_since_call/60)} min ago (expected every {int(expected_interval/60)} min)'
        
        return jsonify({
            'color': color,
            'status': status,
            'detail': detail,
            'countdown_seconds': countdown_seconds,
            'progress_percentage': progress_percentage,
            'next_request_time': next_request_time,
            'interval_seconds': expected_interval,
            'debug_info': status_info
        })
        
    except Exception as e:
        app.logger.error(f"Error getting connection status: {e}")
        return jsonify({
            'color': 'gray',
            'status': 'Status Error',
            'detail': 'Could not determine connection status',
            'countdown_seconds': 0,
            'progress_percentage': 0,
            'next_request_time': time.time(),
            'interval_seconds': 600,
            'error': str(e)
        }), 500

# ============================================================================
# User Management Routes
# ============================================================================

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    """Get list of all users (admin only)"""
    try:
        from database import get_all_web_users
        users = get_all_web_users()
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users]
        })
    except Exception as e:
        logging.error(f"Get users error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user_api():
    """Create new user (admin only)"""
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'user')
        
        # Validate required fields
        if not all([username, email, password]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        # Validate role
        if role not in ['admin', 'user']:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        
        # Check if username or email already exists
        if get_web_user_by_username(username):
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        from database import WebUser
        if WebUser.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already exists'}), 400
        
        # Validate password strength
        password_errors = validate_password_strength(password)
        if password_errors:
            return jsonify({'success': False, 'error': '; '.join(password_errors)}), 400
        
        # Create user
        user = create_web_user(username, email, password, role)
        
        log_security_event('USER_CREATED', current_user.id, details=f'Created user: {username} ({role})')
        
        return jsonify({
            'success': True,
            'message': f'User {username} created successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        logging.error(f"Create user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user_api(user_id):
    """Update user (admin only)"""
    try:
        from database import WebUser
        user = WebUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        data = request.get_json()
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role')
        is_active = data.get('is_active')
        
        # Check for conflicts with other users
        if username and username != user.username:
            existing = get_web_user_by_username(username)
            if existing and existing.id != user_id:
                return jsonify({'success': False, 'error': 'Username already exists'}), 400
            user.username = username
        
        if email and email != user.email:
            existing = WebUser.query.filter_by(email=email).first()
            if existing and existing.id != user_id:
                return jsonify({'success': False, 'error': 'Email already exists'}), 400
            user.email = email
        
        if password:
            password_errors = validate_password_strength(password)
            if password_errors:
                return jsonify({'success': False, 'error': '; '.join(password_errors)}), 400
            user.set_password(password)
        
        if role and role in ['admin', 'user']:
            user.role = role
        
        if is_active is not None:
            user.is_active = bool(is_active)
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_security_event('USER_UPDATED', current_user.id, details=f'Updated user: {user.username}')
        
        return jsonify({
            'success': True,
            'message': f'User {user.username} updated successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        logging.error(f"Update user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user_api(user_id):
    """Delete user (admin only)"""
    try:
        from database import WebUser
        user = WebUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Prevent self-deletion
        if user.id == current_user.id:
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
        
        # Prevent deletion of last admin
        if user.role == 'admin':
            admin_count = WebUser.query.filter_by(role='admin', is_active=True).count()
            if admin_count <= 1:
                return jsonify({'success': False, 'error': 'Cannot delete the last admin user'}), 400
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        log_security_event('USER_DELETED', current_user.id, details=f'Deleted user: {username}')
        
        return jsonify({
            'success': True,
            'message': f'User {username} deleted successfully'
        })
        
    except Exception as e:
        logging.error(f"Delete user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/profile/password', methods=['POST'])
@login_required
def change_password():
    """Change current user's password"""
    try:
        data = request.get_json()
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        # Verify current password
        if not current_user.check_password(current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400
        
        # Check password confirmation
        if new_password != confirm_password:
            return jsonify({'success': False, 'error': 'New passwords do not match'}), 400
        
        # Validate new password strength
        password_errors = validate_password_strength(new_password)
        if password_errors:
            return jsonify({'success': False, 'error': '; '.join(password_errors)}), 400
        
        # Update password
        current_user.set_password(new_password)
        current_user.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_security_event('PASSWORD_CHANGED', current_user.id)
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except Exception as e:
        logging.error(f"Change password error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/current-user', methods=['GET'])
@login_required
def get_current_user_info():
    """Return information about the currently authenticated web user"""
    try:
        if not current_user or not current_user.is_authenticated:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401

        return jsonify({
            'success': True,
            'user': current_user.to_dict(),
            'is_admin': current_user.is_admin()
        })
    except Exception as e:
        logging.error(f"Current user info error: {e}")
        return jsonify({'success': False, 'error': 'Failed to load user info'}), 500

# ============================================================================
# Original Routes (now with authentication)
# ============================================================================

@app.route('/')
@require_setup()
def index():
    """Main page - redirect to dashboard or login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))


# User Management Endpoints

@app.route('/api/user/check')
def check_user():
    """Check if a user exists in the database"""
    user = get_user()
    
    return jsonify({
        'user_exists': user is not None,
        'user': user.to_dict() if user else None
    })

@app.route('/api/user/create', methods=['POST'])
def create_user_endpoint():
    """Create a new user"""
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    # Check if user already exists
    existing_user = get_user()
    if existing_user:
        return jsonify({'success': False, 'error': 'User already exists'}), 400
    
    try:
        user = create_user(data['email'], data['password'])
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': user.to_dict()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/update', methods=['POST'])
def update_user_endpoint():
    """Update user credentials"""
    data = request.get_json()
    
    user = get_user()
    
    try:
        email = (data or {}).get('email')
        password = (data or {}).get('password')

        # If no user exists yet, create one from provided credentials
        if not user:
            if not email or not password:
                return jsonify({'success': False, 'error': 'Email and password required'}), 400
            user = create_user(email, password)
            updated_user = user
        else:
            updated_user = update_user_credentials(
                user.id,
                email=email,
                password=password
            )
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'user': updated_user.to_dict()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/get')
def get_user_endpoint():
    """Get current user information"""
    user = get_user()
    
    if user:
        return jsonify({
            'success': True,
            'user': user.to_dict()
        })
    else:
        return jsonify({'success': False, 'error': 'No user found'}), 404

@app.route('/api/user/remove', methods=['POST'])
def remove_user_endpoint():
    """Remove current user from database with optional data deletion"""
    global cached_data, api_instance
    
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        data = request.get_json() or {}
        delete_data = data.get('deleteData', False)  # Default to keeping data
        
        # Clear global state
        cached_data = None
        api_instance = None
        
        # Optionally delete associated device data first
        if delete_data:
            from database import DeviceData
            DeviceData.query.filter_by(user_id=user.id).delete()
            message = 'User and all data removed successfully'
        else:
            message = 'User removed successfully (data preserved)'
        
        # Remove user from database
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': message,
            'data_deleted': delete_data
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# Data Storage and Retrieval Endpoints


@app.route('/api/data/history')
@login_required
def get_data_history():
    """Get historical device data"""
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        limit = int(request.args.get('limit', 100))
        # Clamp limit to prevent very large payloads
        if limit > 2500:
            limit = 2500
        offset = int(request.args.get('offset', 0))
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        # Debug logging for dynamic aggregation troubleshooting
        if date_from and date_to:
            logging.info(f"History API called with date filtering: {date_from} to {date_to}, limit={limit}")
        
        history = get_device_data_history(user.id, limit=limit, offset=offset, date_from=date_from, date_to=date_to)
        logging.info('History API request limit=%s offset=%s date_from=%s date_to=%s returned=%s first=%s last=%s',
                     limit, offset, date_from, date_to, len(history),
                     history[0].timestamp if history else None,
                     history[-1].timestamp if history else None)
        # Compute total count for the same filters (without limit/offset)
        try:
            from database import get_device_data_history_count
            total_count = get_device_data_history_count(user.id, date_from=date_from, date_to=date_to)
        except Exception:
            total_count = None
        
        # Additional debug info
        if date_from and date_to and history:
            logging.info(f"Returned {len(history)} records, first: {history[0].timestamp}, last: {history[-1].timestamp}")
        
        return jsonify({
            'success': True,
            'data': [item.to_dict() for item in history],
            'count': len(history),
            'total': total_count if total_count is not None else len(history),
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logging.error(f"History API error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/data/daily-energy-summary')
@login_required
def get_daily_energy_summary_endpoint():
    """Get daily energy summary data for charts"""
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        limit = int(request.args.get('limit', 1000))  # Higher default for daily data
        offset = int(request.args.get('offset', 0))
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        daily_summaries = get_daily_energy_summary(
            user.id, 
            limit=limit, 
            offset=offset, 
            date_from=date_from, 
            date_to=date_to
        )
        # ETag check
        etag = _build_etag('daily_energy', user.id, date_from or '', date_to or '', limit, int(last_update or 0))
        if _is_not_modified(etag):
            resp = app.response_class(status=304)
            _apply_cache_headers(resp, etag)
            return resp
        resp = jsonify({
            'success': True,
            'data': daily_summaries,
            'count': len(daily_summaries),
            'limit': limit,
            'offset': offset
        })
        _apply_cache_headers(resp, etag)
        return resp
    except Exception as e:
        logging.error(f"Daily energy summary error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/data/monthly-energy-summary')
@login_required
def get_monthly_energy_summary_endpoint():
    """Get monthly energy summary data for charts"""
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        from database import get_monthly_energy_summary
        
        limit = int(request.args.get('limit', 24))  # Default to 24 months (2 years)
        offset = int(request.args.get('offset', 0))
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        monthly_summaries = get_monthly_energy_summary(
            user.id, 
            limit=limit, 
            offset=offset, 
            date_from=date_from, 
            date_to=date_to
        )
        etag = _build_etag('monthly_energy', user.id, date_from or '', date_to or '', limit, int(last_update or 0))
        if _is_not_modified(etag):
            resp = app.response_class(status=304)
            _apply_cache_headers(resp, etag)
            return resp
        resp = jsonify({
            'success': True,
            'data': monthly_summaries,
            'count': len(monthly_summaries),
            'limit': limit,
            'offset': offset
        })
        _apply_cache_headers(resp, etag)
        return resp
    except Exception as e:
        logging.error(f"Monthly energy summary error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/data/hourly-temperature-summary')
@login_required
def get_hourly_temperature_summary_endpoint():
    """Get hourly temperature summary data for charts (optimized for 2w-1m timeframes)"""
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        limit = int(request.args.get('limit', 500))  # Default to 500 hours (~20 days)
        offset = int(request.args.get('offset', 0))
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        hourly_summaries = get_hourly_temperature_summary(
            user.id, 
            limit=limit, 
            offset=offset, 
            date_from=date_from, 
            date_to=date_to
        )
        etag = _build_etag('hourly_temp', user.id, date_from or '', date_to or '', limit, int(last_update or 0))
        if _is_not_modified(etag):
            resp = app.response_class(status=304)
            _apply_cache_headers(resp, etag)
            return resp
        resp = jsonify({
            'success': True,
            'data': hourly_summaries,
            'count': len(hourly_summaries),
            'limit': limit,
            'offset': offset,
            'aggregation_period': 'hour'
        })
        _apply_cache_headers(resp, etag)
        return resp
    except Exception as e:
        logging.error(f"Hourly temperature summary error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/data/daily-temperature-summary')
@login_required
def get_daily_temperature_summary_endpoint():
    """Get daily temperature summary data for charts (optimized for 6m timeframes)"""
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        limit = int(request.args.get('limit', 200))  # Default to 200 days (~6.5 months)
        offset = int(request.args.get('offset', 0))
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        daily_summaries = get_daily_temperature_summary(
            user.id, 
            limit=limit, 
            offset=offset, 
            date_from=date_from, 
            date_to=date_to
        )
        etag = _build_etag('daily_temp', user.id, date_from or '', date_to or '', limit, int(last_update or 0))
        if _is_not_modified(etag):
            resp = app.response_class(status=304)
            _apply_cache_headers(resp, etag)
            return resp
        resp = jsonify({
            'success': True,
            'data': daily_summaries,
            'count': len(daily_summaries),
            'limit': limit,
            'offset': offset,
            'aggregation_period': 'day'
        })
        _apply_cache_headers(resp, etag)
        return resp
    except Exception as e:
        logging.error(f"Daily temperature summary error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/data/weekly-temperature-summary')
@login_required
def get_weekly_temperature_summary_endpoint():
    """Get weekly temperature summary data for charts (optimized for 1y timeframes)"""
    user = get_user()
    if not user:
        return jsonify({'success': False, 'error': 'No user found'}), 404
    
    try:
        limit = int(request.args.get('limit', 100))  # Default to 100 weeks (~2 years)
        offset = int(request.args.get('offset', 0))
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        weekly_summaries = get_weekly_temperature_summary(
            user.id, 
            limit=limit, 
            offset=offset, 
            date_from=date_from, 
            date_to=date_to
        )
        etag = _build_etag('weekly_temp', user.id, date_from or '', date_to or '', limit, int(last_update or 0))
        if _is_not_modified(etag):
            resp = app.response_class(status=304)
            _apply_cache_headers(resp, etag)
            return resp
        resp = jsonify({
            'success': True,
            'data': weekly_summaries,
            'count': len(weekly_summaries),
            'limit': limit,
            'offset': offset,
            'aggregation_period': 'week'
        })
        _apply_cache_headers(resp, etag)
        return resp
    except Exception as e:
        logging.error(f"Weekly temperature summary error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500






@app.route('/api/data')
@login_required
def get_data():
    """Get latest MELCloud data from database"""
    global cached_data
    
    try:
        # First, try to get latest data from database
        user = get_user()
        if user:
            latest_devices = get_latest_devices_for_dashboard(user.id)
            if latest_devices:
                # Extract location info from first device for user info (they should all be the same structure)
                first_device = latest_devices[0] if latest_devices else {}
                device_structure = first_device.get('structure', {})
                
                # Convert database data to the format expected by frontend
                formatted_data = {
                    "success": True,
                    "login_result": {
                        "user_info": {
                            "name": user.name or user.email,  # Fallback to email if name not set
                            "email": user.email,
                            "country": device_structure.get('country_name') or f"Country {device_structure.get('country', 'Unknown')}",
                            "client": f"Timezone {device_structure.get('timezone', 'Unknown')}"  # Show timezone code
                        }
                    },
                    "device_result": {
                        "devices": latest_devices
                    }
                }
                # Support minimal payload to reduce bytes for callers that don't need full structure fields
                minimal = request.args.get('minimal', 'false').lower() in ('1', 'true', 'yes')
                if minimal:
                    try:
                        slim_devices = []
                        for d in latest_devices:
                            slim_devices.append({
                                'device_id': d.get('device_id'),
                                'device_name': d.get('device_name'),
                                'device_type': d.get('device_type'),
                                # Include just current_data needed for status
                                'current_data': {
                                    'set_temperature': d.get('current_data', {}).get('set_temperature'),
                                    'room_temperature': d.get('current_data', {}).get('room_temperature'),
                                    'outdoor_temperature': d.get('current_data', {}).get('outdoor_temperature'),
                                    'power': d.get('current_data', {}).get('power'),
                                    'operation_mode': d.get('current_data', {}).get('operation_mode'),
                                }
                            })
                        formatted_data['device_result']['devices'] = slim_devices
                        # Trim user_info details if not needed
                        formatted_data['login_result']['user_info'].pop('country', None)
                        formatted_data['login_result']['user_info'].pop('client', None)
                    except Exception:
                        pass
                # ETag from devices snapshot
                try:
                    max_ts = max((d.get('timestamp') or '') for d in latest_devices)
                except Exception:
                    max_ts = ''
                device_ids = ",".join(str(d.get('device_id')) for d in latest_devices if d.get('device_id') is not None)
                etag = _build_etag('api_data', user.id, max_ts, device_ids)
                if _is_not_modified(etag):
                    resp = app.response_class(status=304)
                    _apply_cache_headers(resp, etag)
                    return resp
                resp = jsonify(formatted_data)
                _apply_cache_headers(resp, etag)
                return resp
    except Exception as e:
        print(f"Error getting latest database data: {e}")
    
    # Fallback to cached data if database fetch fails
    if cached_data is None:
        return jsonify({"error": "No data available - please refresh"}), 404
    
    # Remove api_instance from data for JSON serialization
    data_for_json = cached_data.copy()
    data_for_json.pop('api_instance', None)
    
    # Build ETag for cached_data fallback
    try:
        device_ids = ",".join(str(d.get('device_id')) for d in data_for_json.get('device_result', {}).get('devices', []))
    except Exception:
        device_ids = ''
    etag = _build_etag('api_data_cache', device_ids, int(last_update or 0))
    if _is_not_modified(etag):
        resp = app.response_class(status=304)
        _apply_cache_headers(resp, etag)
        return resp
    resp = jsonify(data_for_json)
    _apply_cache_headers(resp, etag)
    return resp


@app.route('/api/devices/minimal')
@login_required
def get_devices_minimal():
    """Get minimal device list for UI (id and name)."""
    try:
        user = get_user()
        if not user:
            return jsonify({'success': False, 'error': 'No user found'}), 404
        devices = get_latest_devices_for_dashboard(user.id) or []
        minimal = [
            {
                'device_id': d.get('device_id'),
                'device_name': d.get('device_name')
            } for d in devices
        ]
        return jsonify({'success': True, 'devices': minimal, 'count': len(minimal)})
    except Exception as e:
        logging.error(f"Error getting minimal devices: {e}")
        return jsonify({'success': False, 'error': 'Failed to load devices'}), 500






@app.route('/api/refresh', methods=['POST'])
@login_required
def refresh_data():
    """Refresh MELCloud data (with rate limiting)"""
    global cached_data, last_update, api_instance
    
    # Check rate limiting
    if api_instance and not api_instance.can_make_request():
        return jsonify({
            "error": f"Rate limited - wait {api_instance.time_until_next_request()} seconds"
        }), 429
    
    try:
        # Use existing API instance if available, or create new one
        if api_instance and api_instance.token:
            # Reuse existing authenticated instance
            import aiohttp
            from melcloud_api import MELCloudAPI
            
            async def refresh_with_existing_api():
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    device_result = await api_instance.get_devices(session)
                    
                    if device_result["success"]:
                        return {
                            "success": True,
                            "login_result": {
                                "success": True,
                                "token": api_instance.token,
                                "user_info": api_instance.user_info
                            },
                            "device_result": device_result,
                            "api_instance": api_instance
                        }
                    else:
                        return {
                            "success": False,
                            "error": device_result.get("error", "Device refresh failed"),
                            "device_result": device_result
                        }
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(refresh_with_existing_api())
            loop.close()
        else:
            # Fall back to full authentication
            user = get_user()
            if not user:
                return jsonify({"success": False, "error": "No user credentials found"}), 401
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            pwd = get_decrypted_melcloud_password(user)
            result = loop.run_until_complete(get_melcloud_data(email=user.email, password=pwd))
            loop.close()
        
        if result["success"]:
            cached_data = result
            last_update = time.time()
            api_instance = result.get("api_instance")
            
            return jsonify({
                "success": True,
                "message": "Data refreshed successfully",
                "timestamp": last_update
            })
        else:
            return jsonify({
                "success": False,
                "error": result.get("error", "Unknown error")
            }), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to refresh data: {str(e)}"
        }), 500


@app.route('/api/initial-load', methods=['POST'])
@login_required
def initial_load():
    """Load initial data on page load"""
    global cached_data, last_update, api_instance
    
    try:
        app.logger.info("Initial load: starting MELCloud login and device fetch (bypass rate limit)")
        # Get user credentials from database
        user = get_user()
        if not user:
            return jsonify({"success": False, "error": "No user credentials found"}), 401
        
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        pwd = get_decrypted_melcloud_password(user)
        result = loop.run_until_complete(get_melcloud_data(email=user.email, password=pwd))
        loop.close()
        
        if result["success"]:
            cached_data = result
            last_update = time.time()
            api_instance = result.get("api_instance")
            
            # Remove api_instance from result for JSON serialization
            result_for_json = result.copy()
            result_for_json.pop('api_instance', None)
            
            app.logger.info("Initial load: MELCloud data fetched successfully; devices=%s", result.get('device_result', {}).get('device_count'))
            return jsonify({
                "success": True,
                "data": result_for_json,
                "timestamp": last_update
            })
        else:
            app.logger.warning("Initial load: MELCloud fetch failed: %s", result.get("error", "Unknown error"))
            return jsonify({
                "success": False,
                "error": result.get("error", "Unknown error")
            }), 500
            
    except Exception as e:
        app.logger.error(f"Initial load: exception: {e}")
        return jsonify({
            "success": False,
            "error": f"Failed to load data: {str(e)}"
        }), 500



@app.route('/api/auto-fetch/status')
def auto_fetch_status():
    """Get auto-fetch status"""
    global auto_fetch_enabled, auto_fetch_thread
    
    thread_alive = auto_fetch_thread and auto_fetch_thread.is_alive()
    
    # Get current interval from database settings
    try:
        from database import get_fetch_interval_seconds, is_api_enabled
        
        api_enabled = is_api_enabled()
        interval_seconds = get_fetch_interval_seconds()
        if interval_seconds is None:
            interval_seconds = 600  # Default 10 minutes
            
    except Exception as e:
        api_enabled = True  # Default fallback
        interval_seconds = 600  # Default 10 minutes
    
    return jsonify({
        'enabled': auto_fetch_enabled,
        'running': thread_alive,
        'api_enabled': api_enabled,
        'interval_seconds': interval_seconds,
        'interval_minutes': interval_seconds // 60
    })


@app.route('/api/auto-fetch/toggle', methods=['POST'])
@admin_required
def toggle_auto_fetch():
    """Toggle auto-fetch on/off"""
    global auto_fetch_enabled
    
    try:
        data = request.get_json() or {}
        enable = data.get('enable', not auto_fetch_enabled)
        
        if enable and not auto_fetch_enabled:
            auto_fetch_enabled = True
            start_auto_fetch()
            return jsonify({
                'success': True,
                'message': 'Auto-fetch enabled',
                'enabled': True
            })
        elif not enable and auto_fetch_enabled:
            stop_auto_fetch()
            return jsonify({
                'success': True,
                'message': 'Auto-fetch disabled',
                'enabled': False
            })
        else:
            return jsonify({
                'success': True,
                'message': f'Auto-fetch already {"enabled" if auto_fetch_enabled else "disabled"}',
                'enabled': auto_fetch_enabled
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to toggle auto-fetch: {str(e)}'
        }), 500


@app.route('/api/auto-fetch/trigger', methods=['POST'])
def trigger_auto_fetch():
    """Manually trigger an auto-fetch cycle"""
    try:
        # Ensure next auto-fetch ignores rate limiting once
        global startup_bypass_rate_limit
        startup_bypass_rate_limit = True
        app.logger.info("Manual trigger: enabling one-time rate-limit bypass for auto-fetch")
        # Run auto-fetch in a separate thread to avoid blocking the request
        def trigger_with_context():
            auto_fetch_data()
        
        fetch_thread = threading.Thread(target=trigger_with_context, daemon=True)
        fetch_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Auto-fetch cycle triggered manually'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to trigger auto-fetch: {str(e)}'
        }), 500


@app.route('/api/health')
def health_check():
    """Comprehensive health check endpoint for monitoring"""
    global db_error_count, service_restart_count, auto_fetch_enabled, auto_fetch_thread
    
    health_status = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'status': 'healthy',
        'checks': {}
    }
    
    try:
        with app.app_context():
            # Database health check
            db_health = check_database_integrity()
            health_status['checks']['database'] = db_health
            
            # Disk space check
            try:
                db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'melcloud.db')
                disk_info = get_disk_space(os.path.dirname(db_path))
                health_status['checks']['disk_space'] = disk_info
            except Exception as e:
                health_status['checks']['disk_space'] = {'error': str(e)}
            
            # Auto-fetch service check
            auto_fetch_status = {
                'enabled': auto_fetch_enabled,
                'thread_alive': auto_fetch_thread and auto_fetch_thread.is_alive(),
                'error_count': db_error_count,
                'max_errors': max_db_errors,
                'restart_count': service_restart_count
            }
            health_status['checks']['auto_fetch'] = auto_fetch_status
            
            # User credentials check
            try:
                user = get_user()
                health_status['checks']['user_credentials'] = {
                    'exists': user is not None,
                    'email': user.email if user else None
                }
            except Exception as e:
                health_status['checks']['user_credentials'] = {'error': str(e)}
            
            # API instance check
            api_status = {
                'authenticated': api_instance is not None and hasattr(api_instance, 'token') and api_instance.token is not None,
                'can_make_request': api_instance.can_make_request() if api_instance else False,
                'time_until_next': api_instance.time_until_next_request() if api_instance else 0
            }
            health_status['checks']['api'] = api_status
            
            # Overall status assessment
            issues = []
            
            if not db_health.get('healthy', False):
                issues.append(f"Database unhealthy: {db_health.get('error', 'unknown')}")
                
            if disk_info.get('available_mb', float('inf')) < 50:
                issues.append(f"Low disk space: {disk_info.get('available_mb', 0)} MB available")
                
            if not auto_fetch_status['thread_alive'] and auto_fetch_status['enabled']:
                issues.append("Auto-fetch thread not running")
                
            if db_error_count >= max_db_errors:
                issues.append(f"Database error threshold exceeded: {db_error_count}/{max_db_errors}")
                
            if not health_status['checks']['user_credentials'].get('exists', False):
                issues.append("No user credentials found")
            
            if issues:
                health_status['status'] = 'degraded' if len(issues) < 3 else 'unhealthy'
                health_status['issues'] = issues
            
            status_code = 200 if health_status['status'] == 'healthy' else 503
            return jsonify(health_status), status_code
            
    except Exception as e:
        return jsonify({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'status': 'unhealthy',
            'error': f'Health check failed: {str(e)}'
        }), 503


@app.route('/api/database/recover', methods=['POST'])
@admin_required
def manual_database_recovery():
    """Manually trigger database recovery"""
    try:
        with app.app_context():
            # Check current database status
            db_health = check_database_integrity()
            
            if db_health.get('healthy', False):
                return jsonify({
                    'success': True,
                    'message': 'Database is already healthy',
                    'health_status': db_health
                })
            
            # Attempt recovery
            recovery_result = recover_database()
            
            # Check status after recovery
            if recovery_result['success']:
                post_recovery_health = check_database_integrity()
                return jsonify({
                    'success': True,
                    'message': 'Database recovery completed',
                    'recovery_action': recovery_result.get('action', 'unknown'),
                    'pre_recovery_status': db_health,
                    'post_recovery_status': post_recovery_health,
                    'backup_path': recovery_result.get('backup_path'),
                    'removed_files': recovery_result.get('removed_files', [])
                })
            else:
                return jsonify({
                    'success': False,
                    'error': recovery_result.get('error', 'Recovery failed'),
                    'pre_recovery_status': db_health
                }), 500
                
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Manual recovery failed: {str(e)}'
        }), 500

# ============================================================================
# Weather API Routes
# ============================================================================


@app.route('/api/weather', methods=['GET'])
@require_setup()
@login_required
def get_weather_data():
    """Get current weather data for device location using Open-Meteo.

    Falls back to MELCloud outdoor temperature if external fetch fails.
    Caches results for a short period to avoid excessive external calls.
    """
    from datetime import datetime

    def _wmo_to_condition_icon(code: int):
        # Basic WMO weather code mapping
        mapping = {
            0: ("Clear", "☀️"),
            1: ("Mainly clear", "🌤️"),
            2: ("Partly cloudy", "🌤️"),
            3: ("Overcast", "☁️"),
            45: ("Fog", "🌫️"), 48: ("Depositing rime fog", "🌫️"),
            51: ("Light drizzle", "🌦️"), 53: ("Drizzle", "🌦️"), 55: ("Heavy drizzle", "🌧️"),
            56: ("Freezing drizzle", "🌧️"), 57: ("Heavy freezing drizzle", "🌧️"),
            61: ("Light rain", "🌧️"), 63: ("Rain", "🌧️"), 65: ("Heavy rain", "🌧️"),
            66: ("Freezing rain", "🌧️"), 67: ("Heavy freezing rain", "🌧️"),
            71: ("Light snow", "❄️"), 73: ("Snow", "❄️"), 75: ("Heavy snow", "❄️"),
            77: ("Snow grains", "❄️"),
            80: ("Rain showers", "🌦️"), 81: ("Rain showers", "🌦️"), 82: ("Heavy rain showers", "🌧️"),
            85: ("Snow showers", "❄️"), 86: ("Heavy snow showers", "❄️"),
            95: ("Thunderstorm", "⛈️"), 96: ("Thunderstorm with hail", "⛈️"), 99: ("Thunderstorm with hail", "⛈️"),
        }
        return mapping.get(int(code), ("Unknown", "❓"))

    # Get latest device data from database (for location and fallback temp)
    device_owner = get_user()
    if not device_owner:
        return jsonify({'error': 'No device data available'}), 404

    latest_devices = get_latest_devices_for_dashboard(device_owner.id)
    if not latest_devices:
        return jsonify({'error': 'No device data available'}), 404

    device = latest_devices[0]
    structure = device.get('structure', {})
    latitude = structure.get('latitude')
    longitude = structure.get('longitude')
    city = structure.get('city', 'Unknown Location')

    # Extract MELCloud outdoor temperature for fallback
    current_data = device.get('current_data', {})
    outdoor_temp = current_data.get('outdoor_temperature')

    # If lat/lon missing, return MELCloud-only data
    if latitude is None or longitude is None:
        return jsonify({
            'temperature': outdoor_temp if outdoor_temp is not None else '--',
            'condition': 'MELCloud Data',
            'location': city if city and city != 'Unknown Location' else 'Unknown',
            'icon': '🏠',
            'description': f'Using MELCloud outdoor temperature for {city}',
            'humidity': None,
            'wind_speed': None,
            'updated': datetime.now().strftime('%H:%M'),
            'provider': 'melcloud'
        })

    # Cache key by rounded location to reduce key proliferation
    cache_key = f"{round(latitude, 3)},{round(longitude, 3)}"
    now_ts = time.time()
    nocache = str(request.args.get('nocache', 'false')).lower() == 'true'
    cached = _weather_cache.get(cache_key)
    if not nocache and cached and (now_ts - cached['ts'] < _WEATHER_CACHE_TTL_SECONDS):
        data = cached['data']
        data['cached'] = True
        return jsonify(data)

    # Build Open-Meteo request
    params = {
        'latitude': latitude,
        'longitude': longitude,
        'current': 'temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code',
        'windspeed_unit': 'kmh',
        'timezone': 'auto'
    }
    url = 'https://api.open-meteo.com/v1/forecast?' + urllib.parse.urlencode(params)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'MELCloud-Dashboard/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
        om = json.loads(raw.decode('utf-8'))

        curr = (om.get('current') or {})
        temp = curr.get('temperature_2m')
        humidity = curr.get('relative_humidity_2m')
        wind = curr.get('wind_speed_10m')
        wcode = curr.get('weather_code')
        condition, icon = _wmo_to_condition_icon(wcode if wcode is not None else -1)

        weather_data = {
            'temperature': temp if temp is not None else (outdoor_temp if outdoor_temp is not None else '--'),
            'condition': condition,
            'location': city if city and city != 'Unknown Location' else f"{round(latitude, 3)},{round(longitude, 3)}",
            'icon': icon,
            'description': f"Open‑Meteo current conditions for {city}",
            'humidity': humidity,
            'wind_speed': wind,
            'updated': datetime.now().strftime('%H:%M'),
            'provider': 'open-meteo'
        }

        # Cache and return
        _weather_cache[cache_key] = {'ts': now_ts, 'data': dict(weather_data)}
        return jsonify(weather_data)

    except Exception as e:
        # On failure, return MELCloud fallback and include error info
        return jsonify({
            'error': f'Weather service error: {str(e)}',
            'fallback': {
                'temperature': outdoor_temp if outdoor_temp is not None else '--',
                'condition': 'MELCloud Data',
                'location': city,
                'icon': '🏠',
                'description': f'Using MELCloud outdoor temperature for {city}',
                'updated': datetime.now().strftime('%H:%M'),
                'provider': 'melcloud'
            }
        }), 200


# ============================================================================
# Schedule Management API Routes
# ============================================================================

@app.route('/api/schedules', methods=['GET'])
@require_setup()
@admin_required
def get_schedules_api():
    """Get all schedules (admin only)"""
    try:
        device_id = request.args.get('device_id', type=int)
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        
        schedules = get_schedules(device_id=device_id, active_only=active_only)
        
        # Add device timezone context to schedules (but don't convert times - let frontend handle it)
        schedule_dicts = []
        for schedule in schedules:
            schedule_dict = schedule.to_dict()
            # Add device timezone context
            schedule_dict['device_timezone'] = get_device_timezone(schedule.device_id)
            schedule_dicts.append(schedule_dict)
        
        return jsonify({
            'success': True,
            'schedules': schedule_dicts
        })
    except Exception as e:
        logging.error(f"Error getting schedules: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules', methods=['POST'])
@require_setup()
@admin_required
def create_schedule_api():
    """Create a new schedule (admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['name', 'device_id', 'schedule_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing field: {field}'}), 400
        
        # Validate schedule type
        valid_types = ['temperature', 'hot_water', 'holiday']
        if data['schedule_type'] not in valid_types:
            return jsonify({'success': False, 'error': f'Invalid schedule type. Must be one of: {valid_types}'}), 400
        
        # Create schedule
        schedule = create_schedule(
            name=data['name'],
            device_id=data['device_id'],
            user_id=current_user.id,
            schedule_type=data['schedule_type'],
            priority=data.get('priority', 1)
        )
        
        # Add rules if provided
        if 'rules' in data and data['rules']:
            for rule_data in data['rules']:
                add_schedule_rule(
                    schedule_id=schedule.id,
                    time_of_day=rule_data['time_of_day'],
                    target_value=rule_data.get('target_value'),
                    day_of_week=rule_data.get('day_of_week'),
                    conditions_json=rule_data.get('conditions_json')
                )
        
        return jsonify({
            'success': True,
            'schedule': get_schedule_by_id(schedule.id).to_dict()
        }), 201
        
    except Exception as e:
        logging.error(f"Error creating schedule: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>', methods=['GET'])
@require_setup()
@admin_required
def get_schedule_api(schedule_id):
    """Get a specific schedule (admin only)"""
    try:
        schedule = get_schedule_by_id(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Schedule not found'}), 404
        
        schedule_dict = schedule.to_dict()
        
        # Add device timezone context (but don't convert times - let frontend handle it)
        schedule_dict['device_timezone'] = get_device_timezone(schedule.device_id)
        
        return jsonify({
            'success': True,
            'schedule': schedule_dict
        })
    except Exception as e:
        logging.error(f"Error getting schedule {schedule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>', methods=['PUT'])
@require_setup()
@admin_required
def update_schedule_api(schedule_id):
    """Update a schedule (admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        schedule = get_schedule_by_id(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Schedule not found'}), 404
        
        # Update schedule fields
        update_fields = ['name', 'priority', 'is_active']
        update_data = {k: v for k, v in data.items() if k in update_fields}
        
        if update_data:
            updated_schedule = update_schedule(schedule_id, **update_data)
        else:
            updated_schedule = schedule
        
        return jsonify({
            'success': True,
            'schedule': updated_schedule.to_dict()
        })
        
    except Exception as e:
        logging.error(f"Error updating schedule {schedule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>', methods=['DELETE'])
@require_setup()
@admin_required
def delete_schedule_api(schedule_id):
    """Delete a schedule (admin only)"""
    try:
        success = delete_schedule(schedule_id)
        if not success:
            return jsonify({'success': False, 'error': 'Schedule not found'}), 404
        
        return jsonify({'success': True, 'message': 'Schedule deleted successfully'})
        
    except Exception as e:
        logging.error(f"Error deleting schedule {schedule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>/toggle', methods=['POST'])
@require_setup()
@admin_required
def toggle_schedule_api(schedule_id):
    """Toggle schedule active status (admin only)"""
    try:
        schedule = toggle_schedule(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Schedule not found'}), 404
        
        return jsonify({
            'success': True,
            'schedule': schedule.to_dict(),
            'message': f'Schedule {"activated" if schedule.is_active else "deactivated"}'
        })
        
    except Exception as e:
        logging.error(f"Error toggling schedule {schedule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>/execute', methods=['POST'])
@require_setup()
@admin_required
def execute_schedule_api(schedule_id):
    """Manually execute a schedule (admin only)"""
    try:
        schedule = get_schedule_by_id(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Schedule not found'}), 404
        
        # Use the schedule execution engine
        engine = get_schedule_engine()
        result = engine.execute_schedule_manually(schedule_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logging.error(f"Error executing schedule {schedule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/schedules/history', methods=['GET'])
@require_setup()
@admin_required
def get_schedule_history_api():
    """Get schedule execution history (admin only)"""
    try:
        schedule_id = request.args.get('schedule_id', type=int)
        limit = request.args.get('limit', 100, type=int)
        
        history = get_schedule_execution_history(schedule_id=schedule_id, limit=limit)
        
        return jsonify({
            'success': True,
            'history': [log.to_dict() for log in history]
        })
        
    except Exception as e:
        logging.error(f"Error getting schedule history: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/next-schedules', methods=['GET'])
@require_setup()
@login_required
def get_next_schedules_api():
    """Get next upcoming heating and hot water schedules"""
    try:
        result = get_next_schedules()
        
        # Format the data for frontend consumption
        response = {
            'success': True,
            'next_heating': None,
            'next_hotwater': None
        }
        
        if result.get('next_heating'):
            heating = result['next_heating']
            response['next_heating'] = {
                'name': heating['schedule_name'],
                'time': heating['time'].strftime('%H:%M'),
                'target_value': heating['target_value'],
                'is_tomorrow': heating['is_tomorrow'],
                'days_away': heating['days_away']
            }
        
        if result.get('next_hotwater'):
            hotwater = result['next_hotwater']
            response['next_hotwater'] = {
                'name': hotwater['schedule_name'],
                'time': hotwater['time'].strftime('%H:%M'),
                'target_value': hotwater['target_value'],
                'is_tomorrow': hotwater['is_tomorrow'],
                'days_away': hotwater['days_away']
            }
        # Optionally include holiday for UI usage in future
        if result.get('next_holiday'):
            holiday = result['next_holiday']
            response['next_holiday'] = {
                'name': holiday['schedule_name'],
                'time': holiday['time'].strftime('%H:%M'),
                'target_value': holiday['target_value'],
                'is_tomorrow': holiday['is_tomorrow']
            }

        return jsonify(response)
        
    except Exception as e:
        logging.error(f"Error getting next schedules: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>/rules', methods=['POST'])
@require_setup()
@admin_required
def add_schedule_rule_api(schedule_id):
    """Add a rule to a schedule (admin only)
    
    Note: time_of_day should be provided in UTC format, as the frontend
    converts device time to UTC before sending to this API
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Validate required fields
        if 'time_of_day' not in data:
            return jsonify({'success': False, 'error': 'Missing field: time_of_day'}), 400
        
        # Check if schedule exists
        schedule = get_schedule_by_id(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Schedule not found'}), 404
        
        # time_of_day is expected to be in UTC (converted by frontend)
        rule = add_schedule_rule(
            schedule_id=schedule_id,
            time_of_day=data['time_of_day'],
            target_value=data.get('target_value'),
            day_of_week=data.get('day_of_week'),
            conditions_json=data.get('conditions_json')
        )
        
        # Add device timezone context to response (but don't convert time - let frontend handle it)
        rule_dict = rule.to_dict()
        rule_dict['device_timezone'] = get_device_timezone(schedule.device_id)
        
        return jsonify({
            'success': True,
            'rule': rule_dict
        }), 201
        
    except Exception as e:
        logging.error(f"Error adding rule to schedule {schedule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>/rules/<int:rule_id>', methods=['DELETE'])
@require_setup()
@admin_required
def delete_schedule_rule_api(schedule_id, rule_id):
    """Delete a schedule rule (admin only)"""
    try:
        success = delete_schedule_rule(rule_id)
        if not success:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404
        
        return jsonify({'success': True, 'message': 'Rule deleted successfully'})
        
    except Exception as e:
        logging.error(f"Error deleting rule {rule_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedule-engine/status', methods=['GET'])
@require_setup()
@admin_required
def get_schedule_engine_status():
    """Get schedule engine status (admin only)"""
    try:
        engine = get_schedule_engine()
        status = engine.get_status()
        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        logging.error(f"Error getting schedule engine status: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedule-engine/start', methods=['POST'])
@require_setup()
@admin_required  
def start_schedule_engine_api():
    """Start the schedule engine (admin only)"""
    try:
        engine = start_schedule_engine(app)
        return jsonify({
            'success': True,
            'message': 'Schedule engine started',
            'status': engine.get_status()
        })
    except Exception as e:
        logging.error(f"Error starting schedule engine: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/schedule-engine/stop', methods=['POST'])
@require_setup()
@admin_required
def stop_schedule_engine_api():
    """Stop the schedule engine (admin only)"""
    try:
        stop_schedule_engine()
        return jsonify({
            'success': True,
            'message': 'Schedule engine stopped'
        })
    except Exception as e:
        logging.error(f"Error stopping schedule engine: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500



# ============================================================================
# Device Configuration API Routes
# ============================================================================

@app.route('/api/device-config', methods=['POST'])
@require_setup()
@admin_required
def create_device_config_api():
    """Create device configuration (admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        device_id = data.get('device_id')
        timezone = data.get('timezone', 'UTC')
        device_name = data.get('device_name')
        
        if not device_id:
            return jsonify({'success': False, 'error': 'device_id is required'}), 400
        
        # Validate timezone
        if timezone not in get_common_timezones():
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        config = create_device_config(device_id, timezone, device_name)
        
        return jsonify({
            'success': True,
            'config': config.to_dict()
        }), 201
        
    except Exception as e:
        logging.error(f"Error creating device config: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/device-config/<int:device_id>', methods=['GET'])
@require_setup()
@admin_required
def get_device_config_api(device_id):
    """Get device configuration (admin only)"""
    try:
        config = get_device_config(device_id)
        if not config:
            # Return default config if none exists
            return jsonify({
                'success': True,
                'config': {
                    'device_id': device_id,
                    'timezone': 'UTC',
                    'device_name': None
                }
            })
        
        return jsonify({
            'success': True,
            'config': config.to_dict()
        })
        
    except Exception as e:
        logging.error(f"Error getting device config {device_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/device-config/<int:device_id>', methods=['PUT'])
@require_setup()
@admin_required
def update_device_config_api(device_id):
    """Update device configuration (admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        timezone = data.get('timezone')
        device_name = data.get('device_name')
        
        # Validate timezone if provided
        if timezone and timezone not in get_common_timezones():
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        config = update_device_config(device_id, timezone, device_name)
        
        return jsonify({
            'success': True,
            'config': config.to_dict()
        })
        
    except Exception as e:
        logging.error(f"Error updating device config {device_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/timezones', methods=['GET'])
def get_timezones_api():
    """Get list of available timezones (public)"""
    try:
        return jsonify({
            'success': True,
            'timezones': get_common_timezones()
        })
    except Exception as e:
        logging.error(f"Error getting timezones: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


def get_server_port():
    """
    Get the server port from command line arguments, environment variable, or default.
    Priority: command line > environment variable > default (8000)
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='MELCloud Web Interface')
    parser.add_argument('--port', '-p', type=int, default=None, 
                       help='Port number to run the server on (default: 8000 or MELCLOUD_PORT env var)')
    args = parser.parse_args()
    
    # Determine port from various sources
    port = None
    source = "default"
    
    # 1. Command line argument takes highest priority
    if args.port is not None:
        port = args.port
        source = "command line"
    # 2. Environment variable second priority  
    elif os.environ.get('MELCLOUD_PORT'):
        try:
            port = int(os.environ.get('MELCLOUD_PORT'))
            source = "environment variable"
        except ValueError:
            logging.warning(f"Invalid MELCLOUD_PORT environment variable: {os.environ.get('MELCLOUD_PORT')}. Using default port.")
            port = 8000
            source = "default (invalid env var)"
    # 3. Default fallback
    else:
        port = 8000
        source = "default"
    
    # Validate port range
    if port < 1024 or port > 65535:
        logging.error(f"Port {port} is out of valid range (1024-65535). Using default port 8000.")
        port = 8000
        source = "default (invalid range)"
    
    logging.info(f"Server will run on port {port} (source: {source})")
    return port


if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('melcloud.log'),
            logging.StreamHandler()
        ]
    )
    
    # Reduce werkzeug (Flask) logging to WARNING to avoid spam
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    # Clear any existing API instance rate limiting state on startup
    if api_instance:
        api_instance.last_request_time = 0  # Reset rate limiting timer
        logging.info("Application startup: Reset API rate limiting timer")
    
    # Reset global state
    cached_data = None
    last_update = 0
    db_error_count = 0
    service_restart_count = 0
    startup_bypass_rate_limit = True  # Reset bypass flag for this startup
    logging.info("Application startup: Cleared cached state")
    
    # Start the schedule execution engine
    try:
        start_schedule_engine(app)
        logging.info("Schedule execution engine started successfully")
    except Exception as e:
        logging.error(f"Failed to start schedule execution engine: {str(e)}")
    
    # Run database migration for new columns
    migrate_database()
    
    # Clean up expired sessions on startup
    try:
        with app.app_context():
            cleanup_old_sessions()
    except Exception as e:
        logging.warning(f"Failed to cleanup old sessions on startup: {e}")
    
    # Start the auto-fetch background thread
    start_auto_fetch()
    
    # Get the configured port
    server_port = get_server_port()
    
    try:
        app.run(debug=True, use_reloader=False, host='0.0.0.0', port=server_port)
    except KeyboardInterrupt:
        logging.info("Shutting down application")
        stop_auto_fetch()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        stop_auto_fetch()
