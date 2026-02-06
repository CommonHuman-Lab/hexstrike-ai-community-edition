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
    cargo rustc \
    golang \
    nmap masscan amass subfinder nuclei dnsenum fierce \
    autorecon nbtscan arp-scan responder netexec \
    enum4linux smbmap theharvester recon-ng sherlock \
    gobuster dirb ffuf nikto sqlmap wpscan dirsearch \
    feroxbuster httpx-toolkit wafw00f \
    arjun paramspider whatweb commix \
    hydra john hashcat medusa patator \
    gdb binwalk radare2 foremost steghide exiftool \
    ghidra checksec \
    trivy \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools not available in Kali repos
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    rm -rf /root/go/pkg /root/.cache/go-build

# Install Rust-based tools not available in Kali repos
RUN cargo install rustscan && \
    rm -rf /root/.cargo/registry /root/.cargo/git

# Install pip-based tools not available in Kali repos
RUN pip3 install --no-cache-dir --break-system-packages volatility3

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
