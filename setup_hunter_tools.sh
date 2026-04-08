#!/bin/bash
# setup_hunter_tools.sh - Install missing core binaries for GhillieSuite-EX on Parrot OS / Linux
# Author: Antigravity

set -euo pipefail

echo "[+] Starting GhillieSuite-EX Hunter Tools installation..."

append_path_export() {
    local rc_file="$1"
    local export_line='export PATH="$PATH:$(go env GOPATH)/bin"'

    touch "$rc_file"
    if ! grep -Fq '$(go env GOPATH)/bin' "$rc_file"; then
        echo "$export_line" >> "$rc_file"
    fi
}

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "[!] Go not found. Installing..."
    sudo apt update && sudo apt install -y golang
fi

# Ensure ~/go/bin is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"
append_path_export "${HOME}/.bashrc"
append_path_export "${HOME}/.zshrc"

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
go install -v github.com/lukasikic/subzy@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/trufflesecurity/trufflehog/v3@latest

# Python Tools
echo "[+] Installing Python-based tools and the local package..."
python3 -m pip install --upgrade pip
python3 -m pip install -e .
python3 -m pip install arjun sqlmap --upgrade

if python3 -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('playwright') else 1)"; then
    echo "[+] Optional browser support detected. Installing Chromium for Playwright..."
    python3 -m playwright install chromium
else
    echo "[i] Playwright is optional. Install with 'python3 -m pip install -e .[browser]' if you want browser-based checks."
fi

echo "[+] Installation complete! Reload your shell or run 'source ~/.bashrc' (or '~/.zshrc') before hunting."
echo "[!] Recommended Execution Command:"
echo "GhillieSuite-EX.sec check-tools"
echo "GhillieSuite-EX.sec hunt --target example.com --scope scope_example.txt"
