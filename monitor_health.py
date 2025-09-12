#!/usr/bin/env python3
"""
MELCloud Service Health Monitor

Simple script to check the health of the MELCloud service.
Can be run manually or scheduled via cron for monitoring.

Usage:
  python monitor_health.py                 # Check health once
  python monitor_health.py --continuous    # Check health every 30 seconds
  python monitor_health.py --recover       # Trigger manual recovery if unhealthy
"""

import requests
import json
import time
import argparse
import sys
from datetime import datetime


def check_health(base_url="http://localhost:8000"):
    """Check service health via the health endpoint"""
    try:
        response = requests.get(f"{base_url}/api/health", timeout=10)
        
        health_data = response.json()
        status = health_data.get('status', 'unknown')
        timestamp = health_data.get('timestamp', 'unknown')
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Health Status: {status.upper()}")
        
        if status != 'healthy':
            print(f"  Status Code: {response.status_code}")
            if 'issues' in health_data:
                print("  Issues:")
                for issue in health_data['issues']:
                    print(f"    - {issue}")
            
            if 'checks' in health_data:
                checks = health_data['checks']
                
                # Database status
                db_check = checks.get('database', {})
                if not db_check.get('healthy', False):
                    print(f"  Database: {db_check.get('error', 'unhealthy')}")
                
                # Auto-fetch status
                auto_fetch = checks.get('auto_fetch', {})
                if not auto_fetch.get('thread_alive', False) and auto_fetch.get('enabled', False):
                    print(f"  Auto-fetch: Thread not running (errors: {auto_fetch.get('error_count', 0)})")
                
                # Disk space
                disk_info = checks.get('disk_space', {})
                if 'available_mb' in disk_info and disk_info['available_mb'] < 100:
                    print(f"  Disk Space: Only {disk_info['available_mb']} MB available")
        
        return response.status_code, health_data
        
    except requests.RequestException as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Health Check Failed: {str(e)}")
        return 500, {'status': 'unreachable', 'error': str(e)}


def trigger_recovery(base_url="http://localhost:8000"):
    """Trigger manual database recovery"""
    try:
        print("Triggering database recovery...")
        response = requests.post(f"{base_url}/api/database/recover", timeout=30)
        
        if response.status_code == 200:
            recovery_data = response.json()
            if recovery_data.get('success', False):
                action = recovery_data.get('recovery_action', 'unknown')
                print(f"Recovery successful: {action}")
                if 'backup_path' in recovery_data:
                    print(f"Backup created at: {recovery_data['backup_path']}")
                return True
            else:
                print(f"Recovery failed: {recovery_data.get('error', 'unknown')}")
                return False
        else:
            print(f"Recovery request failed with status {response.status_code}")
            return False
            
    except requests.RequestException as e:
        print(f"Recovery request failed: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description='MELCloud Service Health Monitor')
    parser.add_argument('--continuous', action='store_true', 
                       help='Run health checks continuously every 30 seconds')
    parser.add_argument('--recover', action='store_true',
                       help='Trigger recovery if service is unhealthy')
    parser.add_argument('--url', default='http://localhost:8000',
                       help='Base URL of the MELCloud service (default: http://localhost:8000)')
    parser.add_argument('--interval', type=int, default=30,
                       help='Interval in seconds for continuous monitoring (default: 30)')
    
    args = parser.parse_args()
    
    if args.continuous:
        print(f"Starting continuous health monitoring (interval: {args.interval} seconds)")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                status_code, health_data = check_health(args.url)
                
                if args.recover and health_data.get('status') in ['degraded', 'unhealthy']:
                    print("Service is unhealthy, attempting recovery...")
                    if trigger_recovery(args.url):
                        # Check health again after recovery
                        time.sleep(5)
                        status_code, health_data = check_health(args.url)
                
                time.sleep(args.interval)
                
        except KeyboardInterrupt:
            print("\nHealth monitoring stopped by user")
            sys.exit(0)
    else:
        # Single health check
        status_code, health_data = check_health(args.url)
        
        if args.recover and health_data.get('status') in ['degraded', 'unhealthy']:
            print("\nService is unhealthy, attempting recovery...")
            if trigger_recovery(args.url):
                # Check health again after recovery
                time.sleep(5)
                status_code, health_data = check_health(args.url)
        
        # Exit with appropriate code
        if health_data.get('status') == 'healthy':
            sys.exit(0)
        elif health_data.get('status') == 'degraded':
            sys.exit(1)
        else:
            sys.exit(2)


if __name__ == '__main__':
    main()