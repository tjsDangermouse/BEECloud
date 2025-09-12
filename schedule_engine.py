#!/usr/bin/env python3
"""
Schedule Execution Engine
Handles automatic execution of MELCloud device schedules
"""

import time
import threading
import logging
from datetime import datetime, timedelta, time as time_obj
import heapq
import asyncio
import aiohttp
from typing import Dict, List, Optional

# Import command functions dynamically to avoid circular imports
from database import (
    get_schedules, log_schedule_execution,
    get_user, get_schedule_by_id
)


class ScheduleExecutionEngine:
    """
    Background service that monitors and executes scheduled device actions
    """
    
    def __init__(self, flask_app=None):
        self.running = False
        self.thread = None
        self.check_interval = 30  # Check every 30 seconds
        self.last_check_time = 0
        self.flask_app = flask_app  # Store Flask app for application context
        # Track executed occurrences to avoid duplicate triggers within the same occurrence
        # key = (schedule_id, next_execution_iso) -> datetime of execution
        self._executed_occurrences = {}
        # In-memory priority queue of upcoming executions: (next_dt, schedule_id, rule_id)
        self._pq = []
        self._last_pq_refresh = 0.0
        self._pq_refresh_interval = 60.0  # seconds
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - Schedule Engine - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ScheduleEngine')
    
    def start(self):
        """Start the schedule execution engine"""
        if self.running:
            self.logger.warning("Schedule engine is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        self.logger.info("Schedule execution engine started")
    
    def stop(self):
        """Stop the schedule execution engine"""
        if not self.running:
            self.logger.warning("Schedule engine is not running")
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.logger.info("Schedule execution engine stopped")
    
    def is_running(self):
        """Check if the engine is currently running"""
        return self.running and self.thread and self.thread.is_alive()
    
    def _run_loop(self):
        """Main execution loop"""
        self.logger.info("Schedule engine loop started")
        
        while self.running:
            try:
                self._check_and_execute_schedules()
                self.last_check_time = time.time()
                
                # Sleep in small intervals to allow for quick shutdown
                sleep_time = 0
                while sleep_time < self.check_interval and self.running:
                    time.sleep(1)
                    sleep_time += 1
                    
            except Exception as e:
                self.logger.error(f"Error in schedule engine loop: {str(e)}")
                time.sleep(10)  # Wait 10 seconds before retrying on error
        
        self.logger.info("Schedule engine loop stopped")
    
    def _purge_executed_occurrences(self, now: datetime):
        """Remove executed entries older than 1 day to bound memory use"""
        cutoff = now - timedelta(days=1)
        to_delete = [key for key, dt in self._executed_occurrences.items() if dt < cutoff]
        for key in to_delete:
            del self._executed_occurrences[key]
        if to_delete:
            self.logger.info(f"Purged {len(to_delete)} executed occurrences older than 1 day")

    def _compute_next_occurrence(self, from_dt: datetime, rule) -> datetime:
        """Compute next occurrence at/after from_dt for a given rule
        
        Note: rule.time_of_day is stored as UTC time, but we need to calculate
        the next occurrence based on device timezone, then return as UTC
        """
        try:
            from database import get_device_timezone, convert_utc_to_device_time, convert_device_time_to_utc
            
            # Get device timezone from schedule's device
            schedule = rule.schedule
            device_timezone = get_device_timezone(schedule.device_id) if schedule else 'UTC'
            
            # If timezone functions fail (e.g., pytz not installed), fallback to simple UTC calculation
            if device_timezone == 'UTC':
                # Simple UTC calculation (original logic)
                rt = rule.time_of_day
                if rule.day_of_week is None:
                    candidate = datetime.combine(from_dt.date(), rt)
                    if candidate <= from_dt:
                        candidate += timedelta(days=1)
                    return candidate
                else:
                    # 0=Monday .. 6=Sunday
                    target_wd = int(rule.day_of_week)
                    days_ahead = (target_wd - from_dt.weekday()) % 7
                    candidate_date = from_dt.date() + timedelta(days=days_ahead)
                    candidate = datetime.combine(candidate_date, rt)
                    if candidate <= from_dt:
                        candidate += timedelta(days=7)
                    return candidate
            
            # Convert stored UTC time to device time for calculation
            rt_utc = rule.time_of_day
            rt_device_str = convert_utc_to_device_time(rt_utc, schedule.device_id)
            rt_device_parts = rt_device_str.split(':')
            rt_device = time_obj(int(rt_device_parts[0]), int(rt_device_parts[1]))
            
            # Calculate next occurrence in device timezone
            if rule.day_of_week is None:
                # Daily rule
                candidate_device = datetime.combine(from_dt.date(), rt_device)
                if candidate_device <= from_dt:
                    candidate_device += timedelta(days=1)
            else:
                # Weekly rule - 0=Monday .. 6=Sunday
                target_wd = int(rule.day_of_week)
                days_ahead = (target_wd - from_dt.weekday()) % 7
                candidate_date = from_dt.date() + timedelta(days=days_ahead)
                candidate_device = datetime.combine(candidate_date, rt_device)
                if candidate_device <= from_dt:
                    candidate_device += timedelta(days=7)
            
            # Convert back to UTC for engine processing
            device_time_str = candidate_device.strftime('%H:%M')
            utc_time_str = convert_device_time_to_utc(device_time_str, schedule.device_id)
            utc_time_parts = utc_time_str.split(':')
            utc_time = time_obj(int(utc_time_parts[0]), int(utc_time_parts[1]))
            candidate_utc = datetime.combine(candidate_device.date(), utc_time)
            
            # Handle day boundary crossings due to timezone conversion
            device_day = candidate_device.date()
            utc_day = candidate_utc.date()
            if utc_day != device_day:
                # Adjust date if timezone conversion crossed day boundary
                day_diff = (utc_day - device_day).days
                candidate_utc = candidate_utc.replace(date=device_day + timedelta(days=day_diff))
            
            return candidate_utc
            
        except Exception as e:
            # Fallback to simple UTC calculation if timezone conversion fails
            self.logger.warning(f"Timezone conversion failed, falling back to UTC: {e}")
            rt = rule.time_of_day
            if rule.day_of_week is None:
                candidate = datetime.combine(from_dt.date(), rt)
                if candidate <= from_dt:
                    candidate += timedelta(days=1)
                return candidate
            else:
                # 0=Monday .. 6=Sunday
                target_wd = int(rule.day_of_week)
                days_ahead = (target_wd - from_dt.weekday()) % 7
                candidate_date = from_dt.date() + timedelta(days=days_ahead)
                candidate = datetime.combine(candidate_date, rt)
                if candidate <= from_dt:
                    candidate += timedelta(days=7)
                return candidate

    def _refresh_pq(self, now: datetime):
        """Rebuild the priority queue of upcoming executions from DB"""
        try:
            from database import get_schedules
            self._pq = []
            schedules = get_schedules(active_only=True)
            count = 0
            for schedule in schedules:
                # Iterate dynamic relationship lazily
                for rule in schedule.rules:
                    try:
                        next_dt = self._compute_next_occurrence(now, rule)
                        heapq.heappush(self._pq, (next_dt, schedule.id, rule.id))
                        count += 1
                    except Exception as e:
                        self.logger.warning(f"Skipping rule {getattr(rule,'id',None)}: {e}")
            self._last_pq_refresh = time.time()
            self.logger.info(f"Rebuilt schedule PQ with {count} entries")
        except Exception as e:
            self.logger.error(f"Failed to refresh schedule PQ: {e}")

    def _check_and_execute_schedules(self):
        """Use in-memory priority queue to trigger due schedules"""
        if not self.flask_app:
            self.logger.error("Flask app not available - cannot access database")
            return

        try:
            with self.flask_app.app_context():
                from database import get_schedule_by_id
                now = datetime.utcnow()

                # Periodic refresh to capture DB changes
                if (not self._pq) or (time.time() - self._last_pq_refresh >= self._pq_refresh_interval):
                    self._refresh_pq(now)

                # Purge old executed entries
                self._purge_executed_occurrences(now)

                # Trigger all due items
                triggered = 0
                while self._pq and self._pq[0][0] <= now:
                    next_dt, schedule_id, rule_id = heapq.heappop(self._pq)
                    key = (schedule_id, next_dt.isoformat())
                    if key in self._executed_occurrences:
                        # Already executed (e.g., on previous loop), schedule the next occurrence and continue
                        schedule = get_schedule_by_id(schedule_id)
                        if schedule:
                            rule = None
                            try:
                                rule = schedule.rules.filter_by(id=rule_id).first()
                            except Exception:
                                rule = None
                            if rule:
                                next_after = self._compute_next_occurrence(next_dt + timedelta(seconds=1), rule)
                                heapq.heappush(self._pq, (next_after, schedule_id, rule_id))
                        continue

                    schedule = get_schedule_by_id(schedule_id)
                    if not schedule or not schedule.is_active:
                        self.logger.info(f"Skipping inactive or missing schedule {schedule_id}")
                        continue
                    # find rule
                    rule = None
                    try:
                        rule = schedule.rules.filter_by(id=rule_id).first()
                    except Exception:
                        rule = None
                    if not rule:
                        self.logger.info(f"Skipping missing rule {rule_id} for schedule {schedule_id}")
                        continue

                    action = {
                        'schedule': schedule,
                        'rule': rule,
                        'next_execution': next_dt,
                    }
                    self.logger.info(
                        f"Triggering schedule '{schedule.name}' (ID {schedule.id}) for device {schedule.device_id} at {next_dt.isoformat()}Z"
                    )
                    self._execute_schedule_action(action)
                    self._executed_occurrences[key] = now
                    triggered += 1

                    # Schedule the next occurrence for this rule
                    next_after = self._compute_next_occurrence(next_dt + timedelta(seconds=1), rule)
                    heapq.heappush(self._pq, (next_after, schedule_id, rule_id))

                if triggered:
                    self.logger.info(f"Triggered {triggered} schedule(s) this cycle")

        except Exception as e:
            self.logger.error(f"Error checking schedules: {str(e)}")
    
    def _execute_schedule_action(self, action):
        """Execute a specific schedule action"""
        schedule = action['schedule']
        rule = action['rule']
        
        try:
            self.logger.info(f"Executing schedule: {schedule.name} (ID: {schedule.id}, Type: {schedule.schedule_type})")
            self.logger.info(f"Rule details - Device: {schedule.device_id}, Time: {rule.time_of_day}, Target: {rule.target_value}")
            
            # Note: API authentication is now handled by the centralized command functions
            
            # Execute the action based on schedule type
            self.logger.info(f"Performing device action for schedule type: {schedule.schedule_type}")
            success, response_data, error_message = self._perform_device_action(
                schedule, rule
            )
            
            # Log the execution
            if self.flask_app:
                with self.flask_app.app_context():
                    log_schedule_execution(
                        schedule_id=schedule.id,
                        success=success,
                        error_message=error_message,
                        device_response_json=response_data
                    )
            
            if success:
                self.logger.info(f"Successfully executed schedule {schedule.name} - Response: {response_data}")
            else:
                self.logger.error(f"Failed to execute schedule {schedule.name}: {error_message}")
                if response_data:
                    self.logger.error(f"API response: {response_data}")
                
        except Exception as e:
            error_msg = f"Exception executing schedule {schedule.id}: {str(e)}"
            self.logger.error(error_msg, exc_info=True)  # Include stack trace
            
            # Log the failed execution
            if self.flask_app:
                with self.flask_app.app_context():
                    log_schedule_execution(
                        schedule_id=schedule.id,
                        success=False,
                        error_message=error_msg
                    )
    
    def _perform_device_action(self, schedule, rule) -> tuple:
        """
        Perform the actual device action
        Returns: (success: bool, response_data: str, error_message: str)
        """
        try:
            # Run the async operation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(
                    self._execute_device_command(schedule, rule)
                )
                return result
            finally:
                loop.close()
                
        except Exception as e:
            return False, None, str(e)
    
    async def _execute_device_command(self, schedule, rule):
        """Execute the device command using centralized command functions"""
        try:
            # Validate device ID
            if not schedule.device_id:
                return False, None, f"Invalid device ID: {schedule.device_id}"
            
            # Get user credentials from database (already in Flask app context)
            if not self.flask_app:
                return False, None, "Flask app not available - cannot access database for user credentials"
            
            with self.flask_app.app_context():
                user = get_user()
                if not user:
                    return False, None, "No user found for API authentication"
            
            # Import command functions dynamically to avoid circular imports
            from app import execute_temperature_command, execute_hot_water_command, execute_holiday_mode_command
            
            # Execute command based on schedule type using centralized functions
            if schedule.schedule_type == 'temperature':
                # Validate temperature value
                if rule.target_value is None:
                    return False, None, "Temperature target value is None"
                
                if not isinstance(rule.target_value, (int, float)):
                    return False, None, f"Temperature target value must be numeric, got: {type(rule.target_value)}"
                
                if rule.target_value < 10 or rule.target_value > 30:
                    return False, None, f"Temperature target value {rule.target_value}°C is outside valid range (10-30°C)"
                
                self.logger.info(f"Setting temperature to {rule.target_value}°C for device {schedule.device_id}")
                from database import get_decrypted_melcloud_password
                user_pwd = get_decrypted_melcloud_password(user)
                result = await execute_temperature_command(
                    email=user.email,
                    password=user_pwd,
                    device_id=schedule.device_id,
                    temperature=rule.target_value,
                    bypass_rate_limit=True
                )
            
            elif schedule.schedule_type == 'hot_water':
                # For hot water, target_value determines forced mode (1.0 = on, 0.0 = off)
                self.logger.info(f"Hot water target_value: {rule.target_value} (type: {type(rule.target_value)})")
                forced_mode = bool(rule.target_value)
                self.logger.info(f"Converted to forced_mode: {forced_mode}")
                action_text = "enabling" if forced_mode else "disabling"
                self.logger.info(f"{action_text.capitalize()} hot water boost for device {schedule.device_id}")
                from database import get_decrypted_melcloud_password
                user_pwd = get_decrypted_melcloud_password(user)
                result = await execute_hot_water_command(
                    email=user.email,
                    password=user_pwd,
                    device_id=schedule.device_id,
                    enable=forced_mode,
                    bypass_rate_limit=True
                )
            
            elif schedule.schedule_type == 'holiday':
                # For holiday mode, target_value determines on/off (1.0 = on, 0.0 = off)
                holiday_mode = bool(rule.target_value)
                action_text = "enabling" if holiday_mode else "disabling"
                self.logger.info(f"{action_text.capitalize()} holiday mode for device {schedule.device_id}")
                from database import get_decrypted_melcloud_password
                user_pwd = get_decrypted_melcloud_password(user)
                result = await execute_holiday_mode_command(
                    email=user.email,
                    password=user_pwd,
                    device_id=schedule.device_id,
                    enable=holiday_mode,
                    bypass_rate_limit=True
                )
            
            else:
                error_msg = f"Unknown schedule type: {schedule.schedule_type}"
                self.logger.error(error_msg)
                return False, None, error_msg
            
            self.logger.info(f"Command execution completed. Success: {result.get('success', False)}")
            
            if result.get('success', False):
                import json
                self.logger.info(f"Schedule execution succeeded: {result}")
                return True, json.dumps(result), None
            else:
                error = result.get('error', 'Unknown error')
                self.logger.error(f"Schedule execution failed - Error: {error}, Full result: {result}")
                return False, json.dumps(result), error
                
        except Exception as e:
            self.logger.error(f"Exception in _execute_device_command: {str(e)}", exc_info=True)
            return False, None, str(e)
    
    def execute_schedule_manually(self, schedule_id: int) -> Dict:
        """
        Manually execute a specific schedule (for testing/admin use)
        Returns execution result
        """
        if not self.flask_app:
            return {'success': False, 'error': 'Flask app not available - cannot access database'}
            
        try:
            with self.flask_app.app_context():
                schedule = get_schedule_by_id(schedule_id)
                if not schedule:
                    return {'success': False, 'error': 'Schedule not found'}
                
                if not schedule.is_active:
                    return {'success': False, 'error': 'Schedule is not active'}
                
                # Get the first rule for manual execution
                if not schedule.rules:
                    return {'success': False, 'error': 'Schedule has no rules'}
                
                rule = list(schedule.rules)[0]  # Use first rule for manual execution
                
                # Create a mock action for execution
                action = {
                    'schedule': schedule,
                    'rule': rule,
                    'next_execution': datetime.utcnow()
                }
                
                self._execute_schedule_action(action)
                
                return {'success': True, 'message': 'Schedule executed successfully'}
            
        except Exception as e:
            error_msg = f"Error manually executing schedule {schedule_id}: {str(e)}"
            self.logger.error(error_msg)
            return {'success': False, 'error': error_msg}
    
    def get_status(self) -> Dict:
        """Get current engine status"""
        return {
            'running': self.is_running(),
            'last_check_time': self.last_check_time,
            'check_interval': self.check_interval,
            'thread_alive': self.thread.is_alive() if self.thread else False
        }
    
    def test_temperature_setting(self, device_id: int, temperature: float) -> Dict:
        """
        Test the temperature setting functionality manually using centralized command functions
        """
        try:
            if not self.flask_app:
                return {
                    'success': False,
                    'error_message': 'Flask app not available - cannot access database for user credentials',
                    'test_device_id': device_id,
                    'test_temperature': temperature
                }
            
            # Get user credentials
            with self.flask_app.app_context():
                user = get_user()
                if not user:
                    return {
                        'success': False,
                        'error_message': 'No user found for API authentication',
                        'test_device_id': device_id,
                        'test_temperature': temperature
                    }
            
            # Execute the test using centralized command function
            async def test_async():
                from app import execute_temperature_command
                from database import get_decrypted_melcloud_password
                user_pwd = get_decrypted_melcloud_password(user)
                return await execute_temperature_command(
                    email=user.email,
                    password=user_pwd,
                    device_id=device_id,
                    temperature=temperature,
                    bypass_rate_limit=True
                )
            
            # Run the async function
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(test_async())
            finally:
                loop.close()
            
            return {
                'success': result.get('success', False),
                'response_data': result,
                'error_message': result.get('error') if not result.get('success') else None,
                'test_device_id': device_id,
                'test_temperature': temperature
            }
            
        except Exception as e:
            self.logger.error(f"Error in test_temperature_setting: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error_message': str(e),
                'test_device_id': device_id,
                'test_temperature': temperature
            }


# Global instance
schedule_engine = None


def get_schedule_engine(flask_app=None) -> ScheduleExecutionEngine:
    """Get the global schedule engine instance"""
    global schedule_engine
    if schedule_engine is None:
        schedule_engine = ScheduleExecutionEngine(flask_app)
    elif flask_app and not schedule_engine.flask_app:
        # Update existing engine with Flask app if not set
        schedule_engine.flask_app = flask_app
    return schedule_engine


def start_schedule_engine(flask_app=None):
    """Start the global schedule engine"""
    engine = get_schedule_engine(flask_app)
    engine.start()
    return engine


def stop_schedule_engine():
    """Stop the global schedule engine"""
    global schedule_engine
    if schedule_engine:
        schedule_engine.stop()


def is_schedule_engine_running() -> bool:
    """Check if the schedule engine is running"""
    global schedule_engine
    return schedule_engine and schedule_engine.is_running()


if __name__ == '__main__':
    # For testing
    logging.basicConfig(level=logging.INFO)
    engine = ScheduleExecutionEngine()
    
    try:
        engine.start()
        print("Schedule engine started. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down schedule engine...")
        engine.stop()
        print("Schedule engine stopped.")
