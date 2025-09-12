import subprocess
import sys
import os

PORT = 8000

def install_requirements():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def run_app():
    subprocess.check_call([sys.executable, "app.py", "--port", str(PORT)])

if __name__ == "__main__":
    install_requirements()
    run_app()