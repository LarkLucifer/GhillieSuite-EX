#!/bin/bash
# setup_hunter_tools.sh - Install missing core binaries for GhillieSuite-EX on Parrot OS / Linux
# Author: Antigravity

set -e

echo "[+] Starting GhillieSuite-EX Hunter Tools installation..."

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "[!] Go not found. Installing..."
    sudo apt update && sudo apt install -y golang
fi

# Ensure ~/go/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

# Project Discovery Tools
echo "[+] Installing ProjectDiscovery tools..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

# Other Core Tools
echo "[+] Installing other core tools..."
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/rootpk/subzy@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Python Tools
echo "[+] Installing Python-based tools..."
pip install arjun sqlmap curl_cffi --upgrade

echo "[+] Installation complete! Please run 'source ~/.bashrc' and then you're ready to hunt."
echo "[!] Recommended Execution Command:"
echo "python main.py --target example.com --turbo --force-auto --waf-evasion --cookie 'SESSION=xxx'"
