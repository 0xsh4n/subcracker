#!/bin/bash

# SubCracker Installation Script
# https://github.com/0xsh4n/subcracker

echo "===================================================="
echo "    SubCracker - Subdomain Reconnaissance Tool"
echo "===================================================="
echo "Starting installation process..."

# Check if Python 3.7+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}')
if [[ -z "$python_version" ]]; then
    echo "[ERROR] Python 3 is not installed or not in PATH."
    echo "Please install Python 3.7+ and try again."
    exit 1
fi

major=$(echo $python_version | cut -d. -f1)
minor=$(echo $python_version | cut -d. -f2)

if [[ $major -lt 3 || ($major -eq 3 && $minor -lt 7) ]]; then
    echo "[ERROR] Python 3.7+ is required. Current version: $python_version"
    echo "Please upgrade Python and try again."
    exit 1
fi

echo "[✓] Python $python_version detected."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to create virtual environment."
    echo "Please install python3-venv package and try again."
    exit 1
fi
echo "[✓] Virtual environment created."

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to activate virtual environment."
    exit 1
fi
echo "[✓] Virtual environment activated."

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip
if [ $? -ne 0 ]; then
    echo "[WARNING] Failed to upgrade pip. Continuing with installation..."
fi

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies."
    exit 1
fi
echo "[✓] Dependencies installed successfully."

# Create default directories
echo "Creating default directories..."
mkdir -p output
mkdir -p wordlists
if [ ! -f "wordlists/subdomains.txt" ]; then
    echo "Downloading default subdomain wordlist..."
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o wordlists/subdomains.txt
    if [ $? -ne 0 ]; then
        echo "[WARNING] Failed to download default wordlist. You'll need to provide your own."
    else
        echo "[✓] Default wordlist downloaded."
    fi
fi

# Make the script executable
chmod +x subcracker.py

# Create a symlink for easier access
if [ -f "subcracker.py" ]; then
    ln -sf $(pwd)/subcracker.py venv/bin/subcracker 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[✓] Created symlink for subcracker command."
    fi
fi

# Installation complete
echo ""
echo "===================================================="
echo "    SubCracker Installation Complete!"
echo "===================================================="
echo ""
echo "To use SubCracker:"
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run SubCracker:"
echo "   python subcracker.py -u example.com -w wordlists/subdomains.txt"
echo ""
echo "For more options, run:"
echo "   python subcracker.py --help"
echo ""
echo "Thank you for installing SubCracker!"
echo "===================================================="
