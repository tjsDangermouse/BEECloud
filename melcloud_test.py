#!/usr/bin/env python3
"""
MELCloud API CLI Test Tool
Based on Home Assistant MELCloud component and pymelcloud library
Shows detailed packet analysis for authentication and API calls
"""

import asyncio
import json
import time
from typing import Optional, Dict, Any
import aiohttp

import os

# Credentials are loaded from environment variables for safety
# Set MELCLOUD_EMAIL and MELCLOUD_PASSWORD before running this tool
EMAIL = os.environ.get("MELCLOUD_EMAIL")
PASSWORD = os.environ.get("MELCLOUD_PASSWORD")

if not EMAIL or not PASSWORD:
    raise SystemExit(
        "Missing credentials. Please set MELCLOUD_EMAIL and MELCLOUD_PASSWORD environment variables."
    )

# MELCloud API configuration
BASE_URL = "https://app.melcloud.com/Mitsubishi.Wifi.Client"
LOGIN_ENDPOINT = "/Login/ClientLogin"
DEVICE_ENDPOINT = "/User/ListDevices"

# Request headers mimicking browser behavior
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/json; charset=UTF-8",
    "Cookie": "policyaccepted=true"
}


def print_separator(title: str):
    """Print a formatted separator with title"""
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print('=' * 60)


def print_request_details(method: str, url: str, headers: Dict[str, str], data: Optional[str] = None):
    """Print detailed request information"""
    print_separator("OUTGOING REQUEST")
    print(f"Method: {method}")
    print(f"URL: {url}")
    print("\nHeaders:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    if data:
        print("\nPayload:")
        try:
            parsed_data = json.loads(data)
            print(json.dumps(parsed_data, indent=2))
        except json.JSONDecodeError:
            print(data)


def print_response_details(response: aiohttp.ClientResponse, content: str, elapsed_time: float):
    """Print detailed response information"""
    print_separator("INCOMING RESPONSE")
    print(f"Status: {response.status} {response.reason}")
    print(f"Response Time: {elapsed_time:.3f}s")
    print("\nHeaders:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    
    print("\nContent:")
    try:
        parsed_content = json.loads(content)
        print(json.dumps(parsed_content, indent=2))
    except json.JSONDecodeError:
        print(content)


async def login_to_melcloud(session: aiohttp.ClientSession) -> Optional[str]:
    """
    Authenticate with MELCloud API and return access token
    Returns the ContextKey token on success, None on failure
    """
    login_url = f"{BASE_URL}{LOGIN_ENDPOINT}"
    
    # Prepare login payload
    login_data = {
        "Email": EMAIL,
        "Password": PASSWORD,
        "Language": 0,
        "AppVersion": "1.19.1.1",
        "Persist": True,
        "CaptchaResponse": None
    }
    
    json_data = json.dumps(login_data)
    
    # Print request details
    print_request_details("POST", login_url, HEADERS, json_data)
    
    try:
        start_time = time.time()
        async with session.post(login_url, headers=HEADERS, data=json_data) as response:
            elapsed_time = time.time() - start_time
            content = await response.text()
            
            # Print response details
            print_response_details(response, content, elapsed_time)
            
            if response.status == 200:
                try:
                    response_json = json.loads(content)
                    context_key = response_json.get("LoginData", {}).get("ContextKey")
                    
                    if context_key:
                        print(f"\n✅ Login successful! Token: {context_key[:20]}...")
                        return context_key
                    else:
                        print(f"\n❌ Login failed: No ContextKey in response")
                        return None
                        
                except json.JSONDecodeError as e:
                    print(f"\n❌ Failed to parse login response: {e}")
                    return None
            else:
                print(f"\n❌ Login failed with status {response.status}")
                return None
                
    except Exception as e:
        print(f"\n❌ Login request failed: {e}")
        return None


async def list_devices(session: aiohttp.ClientSession, token: str):
    """
    List devices using the authenticated token
    """
    device_url = f"{BASE_URL}{DEVICE_ENDPOINT}"
    
    # Add authentication token to headers
    auth_headers = HEADERS.copy()
    auth_headers["X-MitsContextKey"] = token
    
    # Print request details
    print_request_details("GET", device_url, auth_headers)
    
    try:
        start_time = time.time()
        async with session.get(device_url, headers=auth_headers) as response:
            elapsed_time = time.time() - start_time
            content = await response.text()
            
            # Print response details
            print_response_details(response, content, elapsed_time)
            
            if response.status == 200:
                try:
                    response_json = json.loads(content)
                    device_count = len(response_json) if isinstance(response_json, list) else len(response_json.get("Structure", []))
                    print(f"\n✅ Device listing successful! Found {device_count} device(s)")
                    return response_json
                except json.JSONDecodeError as e:
                    print(f"\n❌ Failed to parse device response: {e}")
                    return None
            else:
                print(f"\n❌ Device listing failed with status {response.status}")
                return None
                
    except Exception as e:
        print(f"\n❌ Device listing request failed: {e}")
        return None


async def main():
    """Main function to run the MELCloud API test"""
    print_separator("MELCloud API CLI Test Tool")
    print(f"Testing authentication for: {EMAIL}")
    print(f"Base URL: {BASE_URL}")
    
    # Create aiohttp session
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        
        # Step 1: Authenticate and get token
        print_separator("STEP 1: AUTHENTICATION")
        token = await login_to_melcloud(session)
        
        if not token:
            print("\n🔴 Authentication failed. Exiting.")
            return
        
        # Step 2: List devices using the token
        print_separator("STEP 2: DEVICE LISTING")
        devices = await list_devices(session, token)
        
        if devices is not None:
            print("\n🟢 MELCloud API test completed successfully!")
        else:
            print("\n🟡 Authentication succeeded but device listing failed.")
    
    print_separator("TEST COMPLETE")


if __name__ == "__main__":
    print("Starting MELCloud API test...")
    print("Make sure to update EMAIL and PASSWORD constants in the script!")
    
    # Run the async main function
    asyncio.run(main())
