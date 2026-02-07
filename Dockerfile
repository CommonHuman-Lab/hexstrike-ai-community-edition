# HexStrike AI Community Edition - Dockerfile
# Based on Kali Linux for maximum tool availability
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# ============================================================================
# APT: Build deps, runtimes, and all security tools available in Kali repos
# ============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build dependencies & language runtimes
    build-essential python3-dev libssl-dev liblzma-dev pkg-config \
    python3 python3-pip python3-venv \
    git curl wget sudo gnupg2 ca-certificates \
    cargo rustc \
    golang \
    nodejs npm \
    # ----- RECON -----
    nmap masscan amass subfinder nuclei dnsenum fierce \
    autorecon nbtscan arp-scan responder netexec \
    enum4linux smbmap theharvester recon-ng sherlock \
    exploitdb \
    # ----- WEB -----
    gobuster dirb ffuf nikto sqlmap wpscan dirsearch \
    feroxbuster httpx-toolkit wafw00f \
    arjun paramspider whatweb commix \
    dotdotpwn wfuzz xsser \
    # ----- EXPLOIT / PASSWORD -----
    hydra john hashcat medusa patator \
    metasploit-framework \
    hash-identifier hashid evil-winrm \
    # ----- BINARY ANALYSIS -----
    gdb binwalk radare2 ghidra checksec \
    upx-ucl xxd bsdmainutils \
    # ----- FORENSICS -----
    foremost steghide exiftool \
    scalpel bulk-extractor \
    # ----- NETWORK -----
    smbclient tcpdump tshark aircrack-ng \
    # ----- SECURITY / SSL -----
    sslscan testssl.sh \
    # ----- CLOUD -----
    trivy \
    # ----- BROWSER -----
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# GO: Recon, web & scanning tools not in Kali repos
# ============================================================================
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/haccer/subjack@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/jaeles-project/jaeles@latest && \
    rm -rf /root/go/pkg /root/.cache/go-build

# ============================================================================
# RUST: Port scanning & binary tools not in Kali repos
# ============================================================================
RUN cargo install rustscan x8 pwninit && \
    rm -rf /root/.cargo/registry /root/.cargo/git

# ============================================================================
# RUBY: Binary analysis & forensics gems
# ============================================================================
RUN gem install one_gadget zsteg --no-document

# ============================================================================
# NODE: API testing tools
# ============================================================================
RUN npm install -g newman

# ============================================================================
# PYTHON: Virtual environment for pip packages
# Isolates pip from apt-managed packages (no conflicts, no --break-system-packages)
# ============================================================================
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Standalone pip-based security tools not in Kali repos
RUN pip install --no-cache-dir \
    volatility3 \
    uro \
    ROPgadget \
    ropper \
    sslyze

# ============================================================================
# GIT CLONE: Tools only available from source repos
# ============================================================================
# TruffleHog v3 - secret scanning (binary download, Go module path is broken)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# JWT Tool - JWT security analysis
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool && \
    pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/bash\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool

# GraphW00F - GraphQL fingerprinting
RUN git clone --depth 1 https://github.com/dolevf/graphw00f /opt/graphw00f && \
    printf '#!/bin/bash\nexec python3 /opt/graphw00f/main.py "$@"\n' > /usr/local/bin/graphw00f && \
    chmod +x /usr/local/bin/graphw00f

# Tplmap - server-side template injection
RUN git clone --depth 1 https://github.com/epinna/tplmap /opt/tplmap && \
    pip install --no-cache-dir -r /opt/tplmap/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/bash\nexec python3 /opt/tplmap/tplmap.py "$@"\n' > /usr/local/bin/tplmap && \
    chmod +x /usr/local/bin/tplmap

# NoSQLMap - NoSQL injection
RUN git clone --depth 1 https://github.com/codingo/NoSQLMap /opt/nosqlmap && \
    pip install --no-cache-dir -r /opt/nosqlmap/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/bash\nexec python3 /opt/nosqlmap/nosqlmap.py "$@"\n' > /usr/local/bin/nosqlmap && \
    chmod +x /usr/local/bin/nosqlmap

# Enum4linux-ng - modern SMB enumeration
RUN git clone --depth 1 https://github.com/cddmp/enum4linux-ng /opt/enum4linux-ng && \
    pip install --no-cache-dir -r /opt/enum4linux-ng/requirements.txt 2>/dev/null || true && \
    ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng && \
    chmod +x /opt/enum4linux-ng/enum4linux-ng.py

# HashPump - hash length extension attacks
RUN git clone --depth 1 https://github.com/bwall/HashPump /opt/hashpump && \
    cd /opt/hashpump && make && make install && \
    cd / && rm -rf /opt/hashpump

# ============================================================================
# App dependencies
# ============================================================================
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ============================================================================
# Symlinks: fix binary name mismatches between apt and tool wrappers
# ============================================================================
# theHarvester: apt installs "theharvester", wrapper expects "theHarvester"
RUN ln -sf /usr/bin/theharvester /usr/local/bin/theHarvester 2>/dev/null || true
# testssl: apt installs "testssl.sh", wrapper expects "testssl"
RUN ln -sf /usr/bin/testssl.sh /usr/local/bin/testssl 2>/dev/null || true
# Ghidra headless: apt puts analyzeHeadless in /usr/share/ghidra/support/
RUN ln -sf /usr/share/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless 2>/dev/null || true
# Chromium: browser agent expects google-chrome
RUN ln -sf /usr/bin/chromium /usr/local/bin/google-chrome 2>/dev/null || true

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

CMD ["python3", "hexstrike_server.py", "--port", "8888"]

# ============================================================================
# TOOLS NOT INSTALLED (intentionally excluded - cannot run in Docker)
# ============================================================================
# burpsuite     - Commercial software, requires license
# stegsolve     - Java GUI application, not suitable for headless Docker
# zap-cli       - OWASP ZAP is a large Java app, complex headless setup
# falco         - Requires kernel/eBPF access, not possible in container
# docker-bench  - Requires Docker socket access from inside container
# cloudmapper   - Requires AWS credentials + complex multi-step setup
# pacu          - Requires AWS credentials + complex multi-step setup
# prowler       - Requires cloud provider credentials + complex setup
# scout-suite   - Requires cloud provider credentials + complex setup
# kube-bench    - Requires Kubernetes cluster access
# kube-hunter   - Requires Kubernetes cluster access
# checkov       - Massive dependency tree, causes version conflicts
# terrascan     - Niche IaC tool, complex setup
# clair         - Requires separate database + server setup
# aquatone      - Project archived/unmaintained
# libc-database - Requires git clone + manual database downloads
# volatility v2 - Legacy; v3 is installed instead
# spiderfoot    - Not on PyPI; requires git clone + full web server setup
# outguess      - Not available in Kali repos
# gdb-gef       - GDB plugin, requires interactive gdb config
# gdb-peda      - GDB plugin, requires interactive gdb config
