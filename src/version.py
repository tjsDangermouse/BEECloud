import os

# Base semantic version for the application
BASE_VERSION = "1.0.5"

# Allow override via environment (e.g., Docker/CI build arg)
__version__ = os.getenv("APP_VERSION", BASE_VERSION)

