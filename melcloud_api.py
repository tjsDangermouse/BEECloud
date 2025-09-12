#!/usr/bin/env python3
"""
MELCloud API Library
Modified version of melcloud_test.py that returns structured data instead of printing
"""

import asyncio
import json
import time
from typing import Optional, Dict, List
import aiohttp


# Default credentials (will be overridden by database values)
DEFAULT_EMAIL = ""
DEFAULT_PASSWORD = ""

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


class MELCloudAPI:
    def __init__(self, email=None, password=None):
        self.token = None
        self.user_info = None
        self.last_request_time = 0
        self.email = email if email is not None else DEFAULT_EMAIL
        self.password = password if password is not None else DEFAULT_PASSWORD
        self.bypass_rate_limit = False  # For testing purposes

    def get_min_request_interval(self):
        """Get minimum request interval from database settings"""
        # Allow bypass for testing
        if self.bypass_rate_limit:
            return 0
            
        try:
            # Import here to avoid circular imports
            from database import get_fetch_interval_seconds, is_api_enabled
            
            # Check if API is enabled
            if not is_api_enabled():
                return None  # API disabled
            
            # Get interval from settings, default to 60 seconds if not set
            interval = get_fetch_interval_seconds()
            return interval if interval is not None else 60
        except Exception:
            # Fallback to 60 seconds if database is not available
            return 60

    def can_make_request(self) -> bool:
        """Check if enough time has passed since last request"""
        min_interval = self.get_min_request_interval()
        if min_interval is None:
            return False  # API disabled
        return time.time() - self.last_request_time >= min_interval

    def time_until_next_request(self) -> int:
        """Returns seconds until next request is allowed"""
        min_interval = self.get_min_request_interval()
        if min_interval is None:
            return float('inf')  # API disabled, infinite wait
        elapsed = time.time() - self.last_request_time
        remaining = max(0, min_interval - elapsed)
        return int(remaining)

    async def login(self, session: aiohttp.ClientSession) -> Dict:
        """
        Authenticate with MELCloud API and return login result
        """
        login_url = f"{BASE_URL}{LOGIN_ENDPOINT}"
        
        # Prepare login payload
        login_data = {
            "Email": self.email,
            "Password": self.password,
            "Language": 0,
            "AppVersion": "1.19.1.1",
            "Persist": True,
            "CaptchaResponse": None
        }
        
        json_data = json.dumps(login_data)
        
        try:
            start_time = time.time()
            async with session.post(login_url, headers=HEADERS, data=json_data) as response:
                elapsed_time = time.time() - start_time
                content = await response.text()
                
                request_info = {
                    "method": "POST",
                    "url": login_url,
                    "headers": dict(HEADERS),
                    "payload": login_data,
                    "response_time": elapsed_time,
                    "status_code": response.status
                }
                
                if response.status == 200:
                    try:
                        response_json = json.loads(content)
                        login_data = response_json.get("LoginData", {})
                        context_key = login_data.get("ContextKey")
                        
                        if context_key:
                            self.token = context_key
                            self.user_info = {
                                "name": login_data.get("Name", "Unknown"),
                                "email": login_data.get("Email", self.email),
                                "country": login_data.get("Country", "Unknown"),
                                "language": login_data.get("Language", 0),
                                "client": login_data.get("Client", "Unknown"),
                                "terms": login_data.get("Terms", "Unknown")
                            }
                            self.last_request_time = time.time()
                            
                            return {
                                "success": True,
                                "token": context_key,
                                "user_info": self.user_info,
                                "request_info": request_info,
                                "response": response_json
                            }
                        else:
                            return {
                                "success": False,
                                "error": "No ContextKey in response",
                                "request_info": request_info,
                                "response": response_json
                            }
                            
                    except json.JSONDecodeError as e:
                        return {
                            "success": False,
                            "error": f"Failed to parse login response: {e}",
                            "request_info": request_info,
                            "response": content
                        }
                else:
                    return {
                        "success": False,
                        "error": f"Login failed with status {response.status}",
                        "request_info": request_info,
                        "response": content
                    }
                    
        except Exception as e:
            return {
                "success": False,
                "error": f"Login request failed: {e}",
                "request_info": {
                    "method": "POST",
                    "url": login_url,
                    "error": str(e)
                }
            }

    async def get_devices(self, session: aiohttp.ClientSession) -> Dict:
        """
        Get devices using the authenticated token
        """
        if not self.token:
            return {
                "success": False,
                "error": "Not authenticated - no token available"
            }

        if not self.can_make_request():
            return {
                "success": False,
                "error": f"Rate limited - wait {self.time_until_next_request()} seconds"
            }

        device_url = f"{BASE_URL}{DEVICE_ENDPOINT}"
        
        # Add authentication token to headers
        auth_headers = HEADERS.copy()
        auth_headers["X-MitsContextKey"] = self.token
        
        try:
            start_time = time.time()
            async with session.get(device_url, headers=auth_headers) as response:
                elapsed_time = time.time() - start_time
                content = await response.text()
                
                request_info = {
                    "method": "GET",
                    "url": device_url,
                    "headers": dict(auth_headers),
                    "response_time": elapsed_time,
                    "status_code": response.status
                }
                
                if response.status == 200:
                    try:
                        response_json = json.loads(content)
                        self.last_request_time = time.time()
                        
                        # Parse device information
                        devices = []
                        if isinstance(response_json, list):
                            # Direct list of structures
                            for structure in response_json:
                                devices.extend(self._parse_structure(structure))
                        elif "Structure" in response_json:
                            # Nested structure format
                            for structure in response_json["Structure"]:
                                devices.extend(self._parse_structure(structure))
                        
                        return {
                            "success": True,
                            "devices": devices,
                            "device_count": len(devices),
                            "request_info": request_info,
                            "response": response_json
                        }
                        
                    except json.JSONDecodeError as e:
                        return {
                            "success": False,
                            "error": f"Failed to parse device response: {e}",
                            "request_info": request_info,
                            "response": content
                        }
                else:
                    return {
                        "success": False,
                        "error": f"Device listing failed with status {response.status}",
                        "request_info": request_info,
                        "response": content
                    }
                    
        except Exception as e:
            return {
                "success": False,
                "error": f"Device listing request failed: {e}",
                "request_info": {
                    "method": "GET",
                    "url": device_url,
                    "error": str(e)
                }
            }

    def _parse_structure(self, structure: Dict) -> List[Dict]:
        """Parse a structure and extract device information"""
        devices = []
        
        # Structure info
        structure_info = {
            "structure_name": structure.get("Name", structure.get("StructureName", "Unknown")),
            "address_line1": structure.get("AddressLine1", ""),
            "address_line2": structure.get("AddressLine2", ""),
            "city": structure.get("City", "Unknown"),
            "postcode": structure.get("Postcode", ""),
            "country": structure.get("Country", "Unknown"),
            "country_name": structure.get("CountryName", ""),
            "timezone": structure.get("TimeZone", "Unknown"),
            "latitude": structure.get("Latitude"),
            "longitude": structure.get("Longitude"),
            "location_id": structure.get("Location"),
            "building_type": structure.get("BuildingType"),
            "property_type": structure.get("PropertyType"),
            "date_built": structure.get("DateBuilt")
        }
        
        # First check for devices directly in Structure -> Devices
        direct_devices = structure.get("Structure", {}).get("Devices", [])
        for device in direct_devices:
            parsed_device = self._parse_device(device, structure_info, "Unknown", "Unknown")
            devices.append(parsed_device)
        
        # Also check the traditional Floors -> Areas -> Devices structure
        floors = structure.get("Floors", [])
        for floor in floors:
            floor_name = floor.get("FloorName", "Unknown")
            areas = floor.get("Areas", [])
            
            for area in areas:
                area_name = area.get("AreaName", "Unknown")
                device_list = area.get("Devices", [])
                
                for device in device_list:
                    parsed_device = self._parse_device(device, structure_info, floor_name, area_name)
                    devices.append(parsed_device)
        
        return devices
    
    def _parse_device(self, device: Dict, structure_info: Dict, floor_name: str, area_name: str) -> Dict:
        """Parse individual device data"""
        # Extract device data - check both direct properties and Device sub-object
        device_data = device.get("Device", device)  # Some devices have nested Device object
        
        return {
            "device_id": device.get("DeviceID") or device_data.get("DeviceID"),
            "serial_number": device.get("SerialNumber") or device_data.get("SerialNumber"),
            "mac_address": device.get("MacAddress") or device_data.get("MacAddress"),
            "device_name": device.get("DeviceName", "Unknown"),
            "device_type": device.get("Type") or device_data.get("DeviceType"),
            "model": device_data.get("Units", [{}])[0].get("Model", "Unknown") if device_data.get("Units") else "Unknown",
            "floor": floor_name,
            "area": area_name,
            "online": not device_data.get("Offline", False),  # Offline is inverted
            "last_communication": device_data.get("LastTimeStamp"),
            "structure": structure_info,
            "capabilities": {
                "has_thermostat": device_data.get("HasThermostatZone1", False) or device_data.get("HasThermostatZone2", False),
                "has_energy": device_data.get("HasEnergyConsumedMeter", False),
                "has_wifi": device_data.get("WifiSignalStrength") is not None,
                "has_zone": device_data.get("HasZone2", False),
                "can_heat": device_data.get("CanHeat", False),
                "can_cool": device_data.get("CanCool", False),
                "has_hot_water": device_data.get("HasHotWaterTank", False)
            },
            "current_data": {
                "room_temperature": device_data.get("RoomTemperatureZone1"),
                "room_temperature_zone2": device_data.get("RoomTemperatureZone2"),
                "set_temperature": device_data.get("SetTemperatureZone1"),
                "set_temperature_zone2": device_data.get("SetTemperatureZone2"),
                "tank_temperature": device_data.get("TankWaterTemperature"),
                "set_tank_temperature": device_data.get("SetTankWaterTemperature"),
                "outdoor_temperature": device_data.get("OutdoorTemperature"),
                "flow_temperature": device_data.get("FlowTemperature"),
                "return_temperature": device_data.get("ReturnTemperature"),
                "operation_mode": device_data.get("OperationMode"),
                "operation_mode_zone1": device_data.get("OperationModeZone1"),
                "operation_mode_zone2": device_data.get("OperationModeZone2"),
                "power": device_data.get("Power", False),
                "eco_hot_water": device_data.get("EcoHotWater", False),
                "forced_hot_water": device_data.get("ForcedHotWaterMode", False),
                "holiday_mode": device_data.get("HolidayMode", False),
                "wifi_signal": device_data.get("WifiSignalStrength"),
                "wifi_adapter_status": device_data.get("WifiAdapterStatus"),
                "unit_status": device_data.get("UnitStatus"),
                "effective_flags": device_data.get("EffectiveFlags"),
                "defrost_mode": device_data.get("DefrostMode"),
                "last_legionella_activation_time": device_data.get("LastLegionellaActivationTime"),
                "last_reset": device_data.get("LastReset"),
                "daily_energy_consumed_date": device_data.get("DailyEnergyConsumedDate"),
                "daily_energy_produced_date": device_data.get("DailyEnergyProducedDate"),
                "daily_energy_consumed": {
                    "heating": device_data.get("DailyHeatingEnergyConsumed"),
                    "cooling": device_data.get("DailyCoolingEnergyConsumed"),
                    "hot_water": device_data.get("DailyHotWaterEnergyConsumed")
                },
                "daily_energy_produced": {
                    "heating": device_data.get("DailyHeatingEnergyProduced"),
                    "cooling": device_data.get("DailyCoolingEnergyProduced"),
                    "hot_water": device_data.get("DailyHotWaterEnergyProduced")
                }
            }
        }

    # ============================================================================
    # Device Control Commands
    # ============================================================================
    
    async def send_device_command(self, session: aiohttp.ClientSession, device_id: int, device_state: Dict, bypass_rate_limit: bool = False) -> Dict:
        """
        Send a device state update to MELCloud (pymelcloud approach)
        For Air-to-Water units, uses /Device/SetAtw endpoint
        device_state should be the complete device state dict
        """
        if not self.token:
            return {
                "success": False,
                "error": "Not authenticated - no token available"
            }

        # Allow bypassing rate limit for control commands
        if not bypass_rate_limit and not self.can_make_request():
            return {
                "success": False,
                "error": "Rate limit active",
                "time_until_next_request": self.time_until_next_request()
            }

        # Air-to-Water command endpoint
        command_url = f"{BASE_URL}/Device/SetAtw"
        
        # Add authentication token to headers
        auth_headers = HEADERS.copy()
        auth_headers["X-MitsContextKey"] = self.token
        
        # Ensure DeviceID is set correctly
        payload = device_state.copy()
        payload["DeviceID"] = device_id
        
        try:
            start_time = time.time()
            async with session.post(command_url, headers=auth_headers, json=payload) as response:
                content = await response.text()
                elapsed_time = time.time() - start_time
                
                request_info = {
                    "method": "POST",
                    "url": command_url,
                    "headers": {k: v for k, v in auth_headers.items() if k != "X-MitsContextKey"},  # Don't log token
                    "payload_summary": {
                        "DeviceID": payload.get("DeviceID"),
                        "EffectiveFlags": payload.get("EffectiveFlags"),
                        "SetTemperatureZone1": payload.get("SetTemperatureZone1"),
                        "HasPendingCommand": payload.get("HasPendingCommand"),
                        "Power": payload.get("Power")
                    },
                    "response_time": elapsed_time,
                    "status_code": response.status
                }
                
                if response.status == 200:
                    try:
                        response_json = json.loads(content)
                        self.last_request_time = time.time()
                        
                        return {
                            "success": True,
                            "response": response_json,
                            "request_info": request_info
                        }
                        
                    except json.JSONDecodeError as e:
                        return {
                            "success": False,
                            "error": f"Failed to parse command response: {e}",
                            "request_info": request_info,
                            "response": content
                        }
                else:
                    return {
                        "success": False,
                        "error": f"Command failed with status {response.status}",
                        "request_info": request_info,
                        "response": content
                    }
                    
        except Exception as e:
            return {
                "success": False,
                "error": f"Command request failed: {e}"
            }

    async def get_device_state(self, session: aiohttp.ClientSession, device_id: int, bypass_rate_limit: bool = False) -> Dict:
        """Get complete current device state from MELCloud"""
        if not self.token:
            return {
                "success": False,
                "error": "Not authenticated - no token available"
            }

        # Temporarily bypass rate limit for debug operations
        original_bypass = self.bypass_rate_limit
        if bypass_rate_limit:
            self.bypass_rate_limit = True

        try:
            # Get device list to find the specific device state
            device_result = await self.get_devices(session)
            if not device_result["success"]:
                return device_result
        finally:
            # Restore original rate limit setting
            self.bypass_rate_limit = original_bypass
            
        # Find the device with matching ID
        target_device = None
        for device in device_result.get("devices", []):
            # Check both processed and raw field names for device ID
            device_data = device.get("device_data", {})
            if (device.get("device_id") == device_id or 
                device.get("DeviceID") == device_id or 
                device_data.get("DeviceID") == device_id):
                # If device_data is empty, use the device object itself
                # This happens when the MELCloud API returns processed data
                if device_data:
                    target_device = device_data
                else:
                    target_device = device
                break
                
        if not target_device:
            # Debug: show what devices are available
            available_devices = []
            for device in device_result.get("devices", []):
                device_data = device.get("device_data", {})
                device_info = {
                    "device_id_field": device.get("device_id"),
                    "DeviceID_field": device.get("DeviceID"), 
                    "device_data_DeviceID": device_data.get("DeviceID"),
                    "device_keys": list(device.keys())[:5],  # First 5 keys
                    "device_data_keys": list(device_data.keys())[:5]  # First 5 keys from device_data
                }
                available_devices.append(device_info)
            
            return {
                "success": False,
                "error": f"Device {device_id} not found",
                "debug_available_devices": available_devices,
                "total_devices": len(device_result.get("devices", []))
            }
            
        return {
            "success": True,
            "device_data": target_device
        }

    def round_temperature(self, temperature: float) -> float:
        """Round temperature to 0.5 precision like pymelcloud does"""
        return round(temperature * 2) / 2

    async def set_temperature(self, session: aiohttp.ClientSession, device_id: int, temperature: float) -> Dict:
        """Set room temperature for Air-to-Water device using pymelcloud approach"""
        if not isinstance(temperature, (int, float)) or temperature < 10 or temperature > 30:
            return {
                "success": False,
                "error": "Temperature must be between 10-30°C"
            }
        
        # Get current device state
        state_result = await self.get_device_state(session, device_id)
        if not state_result["success"]:
            return state_result
        
        device_data = state_result["device_data"]
        current_data = device_data.get("current_data", {})
        
        # Round temperature to 0.5 precision
        rounded_temp = self.round_temperature(temperature)
        
        # Build MELCloud command payload using the correct structure
        # Based on debug results, we need to construct the payload manually
        new_state = {
            "DeviceID": device_data.get("device_id"),
            "DeviceType": device_data.get("device_type", 1),  # Air-to-Water
            "SetTemperatureZone1": rounded_temp,
            "EffectiveFlags": 0x200000080,  # pymelcloud flag for Zone 1 temp
            "HasPendingCommand": True,
            # Copy other required fields if they exist
            "Power": current_data.get("power", True),
            # Preserve all temperature settings
            "SetTemperatureZone2": current_data.get("set_temperature_zone2"),
            "SetTankWaterTemperature": current_data.get("set_tank_temperature"),
            # Preserve operation mode settings
            "OperationMode": current_data.get("operation_mode"),
            "OperationModeZone1": current_data.get("operation_mode_zone1"),
            "OperationModeZone2": current_data.get("operation_mode_zone2"),
            # Preserve hot water and mode settings
            "EcoHotWater": current_data.get("eco_hot_water", False),
            "ForcedHotWaterMode": current_data.get("forced_hot_water", False),
            "HolidayMode": current_data.get("holiday_mode", False)
        }
            
        result = await self.send_device_command(session, device_id, new_state, bypass_rate_limit=True)
        if result["success"]:
            result["action"] = f"Set temperature to {rounded_temp}°C"
        return result

    async def force_hot_water(self, session: aiohttp.ClientSession, device_id: int, enable: bool) -> Dict:
        """Enable/disable forced hot water mode"""
        if not isinstance(enable, bool):
            return {
                "success": False,
                "error": "Enable must be true or false"
            }
        
        # Get current device state first (like temperature command does)
        state_result = await self.get_device_state(session, device_id)
        if not state_result["success"]:
            return state_result
        
        device_data = state_result["device_data"]
        current_data = device_data.get("current_data", {})
        
        # Build complete MELCloud command payload (matching temperature command pattern)
        new_state = {
            "DeviceID": device_data.get("device_id"),
            "DeviceType": device_data.get("device_type", 1),  # Air-to-Water
            "ForcedHotWaterMode": enable,
            "EffectiveFlags": 0x10000,  # Hot water boost flag (from pymelcloud source code)
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
        
        result = await self.send_device_command(session, device_id, new_state, bypass_rate_limit=True)
        if result["success"]:
            action = "enabled" if enable else "disabled"
            result["action"] = f"Hot water boost {action}"
        return result

    async def set_holiday_mode(self, session: aiohttp.ClientSession, device_id: int, enable: bool) -> Dict:
        """Enable/disable holiday mode"""
        if not isinstance(enable, bool):
            return {
                "success": False,
                "error": "Enable must be true or false"
            }
        
        # Get current device state first (like temperature command does)
        state_result = await self.get_device_state(session, device_id)
        if not state_result["success"]:
            return state_result
        
        device_data = state_result["device_data"]
        current_data = device_data.get("current_data", {})
        
        # Build complete MELCloud command payload (matching temperature command pattern)
        new_state = {
            "DeviceID": device_data.get("device_id"),
            "DeviceType": device_data.get("device_type", 1),  # Air-to-Water
            "HolidayMode": enable,
            "EffectiveFlags": 0x40,  # Holiday mode flag (likely correct based on MELCloud patterns)
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
        
        result = await self.send_device_command(session, device_id, new_state, bypass_rate_limit=True)
        if result["success"]:
            action = "enabled" if enable else "disabled"
            result["action"] = f"Holiday mode {action}"
        return result
    
    async def set_hot_water(self, session: aiohttp.ClientSession, device_id: int, enable: bool) -> Dict:
        """Alias for force_hot_water method to maintain compatibility with schedule engine"""
        return await self.force_hot_water(session, device_id, enable)


async def get_melcloud_data(email=None, password=None) -> Dict:
    """
    Main function to get all MELCloud data
    Returns structured data for web display
    """
    api = MELCloudAPI(email=email, password=password)
    # For initial authentication flow, temporarily reduce rate limiting
    api.bypass_rate_limit = True  # Allow immediate requests for initial auth flow
    
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        
        # Step 1: Login
        login_result = await api.login(session)
        
        if not login_result["success"]:
            return {
                "success": False,
                "error": login_result["error"],
                "login_result": login_result
            }
        
        # Step 2: Get devices (with reduced rate limiting for initial flow)
        device_result = await api.get_devices(session)
        
        # Restore normal rate limiting for future requests
        api.bypass_rate_limit = False
        
        if device_result["success"]:
            return {
                "success": True,
                "login_result": login_result,
                "device_result": device_result,
                "api_instance": api
            }
        else:
            return {
                "success": False,
                "error": device_result.get("error", "Device listing failed"),
                "login_result": login_result,
                "device_result": device_result,
                "api_instance": api
            }


# For backwards compatibility with the CLI version
async def main():
    """CLI compatibility function"""
    result = await get_melcloud_data()
    
    if result["success"]:
        print("✅ MELCloud API test completed successfully!")
        print(f"User: {result['login_result']['user_info']['name']}")
        print(f"Devices found: {result['device_result']['device_count']}")
    else:
        print(f"❌ MELCloud API test failed: {result.get('error', 'Unknown error')}")
    
    return result


if __name__ == "__main__":
    asyncio.run(main())