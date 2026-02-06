# HexStrike AI Community Edition - Dockerfile
# Based on Kali Linux for maximum tool availability
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install build deps, Python, and security tools available via apt
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential python3-dev \
    python3 python3-pip python3-venv \
    git curl wget sudo gnupg2 ca-certificates \
    # Network & Recon
    nmap masscan amass subfinder nuclei dnsenum fierce \
    rustscan autorecon nbtscan arp-scan responder netexec \
    enum4linux smbmap theharvester recon-ng sherlock \
    # Web App Security
    gobuster dirb ffuf nikto sqlmap wpscan dirsearch \
    feroxbuster httpx-toolkit katana wafw00f \
    dalfox arjun paramspider whatweb commix \
    # Password & Auth
    hydra john hashcat medusa patator \
    # Binary Analysis & Forensics
    gdb binwalk radare2 foremost steghide exiftool \
    volatility3 ghidra checksec \
    # Cloud & Container
    trivy \
    # Browser requirements
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY . .

# Chromium symlink for browser agent
RUN ln -s /usr/bin/chromium /usr/bin/google-chrome 2>/dev/null || true

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

CMD ["python3", "hexstrike_server.py", "--port", "8888"]
