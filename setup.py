#!/usr/bin/env python3
"""
Setup script for WebReputation tool.
"""

import os
import sys
import subprocess


def install_requirements():
    """Install required dependencies."""
    print("Installing required dependencies...")
    
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False


def create_directories():
    """Create necessary directories."""
    directories = ['payloads', 'results']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")


def setup_config():
    """Setup configuration file."""
    config_file = 'config.yaml'
    
    if os.path.exists(config_file):
        print(f"Configuration file already exists: {config_file}")
        
        while True:
            choice = input("Do you want to configure VirusTotal API key? (y/n): ").lower()
            if choice in ['y', 'yes']:
                api_key = input("Enter your VirusTotal API key: ").strip()
                if api_key:
                    # Update config file
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    content = content.replace('YOUR_VIRUSTOTAL_API_KEY_HERE', api_key)
                    
                    with open(config_file, 'w') as f:
                        f.write(content)
                    
                    print("✅ VirusTotal API key configured")
                break
            elif choice in ['n', 'no']:
                print("⚠️  VirusTotal API key not configured. VT analysis will be skipped.")
                break
            else:
                print("Please enter 'y' or 'n'")


def main():
    """Main setup function."""
    print("WebReputation Tool Setup")
    print("=" * 30)
    
    # Install dependencies
    if not install_requirements():
        print("Setup failed due to dependency installation error")
        return 1
    
    # Create directories
    create_directories()
    
    # Setup configuration
    setup_config()
    
    print("\n✅ Setup completed successfully!")
    print("\nYou can now run the tool using:")
    print("  python webreputation.py -u <URL>")
    print("\nFor help:")
    print("  python webreputation.py --help")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())