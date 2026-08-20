<div align="center">
<img src="assets/nyxstrike-logo.png" alt="NyxStrike" width="220"/>

# NyxStrike

### AI-powered offensive security orchestration engine

</div>

## What is NyxStrike?

NyxStrike connects LLM agents to real offensive security tools and executes full attack chains — from recon to exploitation.

**200+ tools · 50+ categories · AI decision engine · Tamper-evident evidence chain**

---

## 🚀 Quick Start (Installation)

> Get a full offensive security environment running in minutes.

```bash
git clone https://github.com/CommonHuman-Lab/nyxstrike.git
cd nyxstrike

./nyxstrike.sh -a               # Setup + start server
./nyxstrike.sh -a -t            # + install external tools

```

> Full flag reference: [Wiki — Installation & Flags](https://github.com/CommonHuman-Lab/nyxstrike/wiki/Installation-and-Flags)

### Verify Setup

Open [http://localhost:8888](http://localhost:8888) to access the dashboard.

> Some tools (e.g. `nmap`, `masscan`) require elevated privileges for specific scan modes. Use a dedicated test VM and least-privilege setup where possible.

---

## 🔌 AI Agent Integrations (MCP)

Connect NyxStrike to any MCP-compatible AI client — OpenCode, Cursor, Claude Desktop, VS Code Copilot, Roo Code, and more.

> Open [http://localhost:8888/#/help](http://localhost:8888/#/help) for help with configurations.

### Universal MCP Command

```bash
/path/to/nyxstrike/nyxstrike-env/bin/python3 \
  /path/to/nyxstrike/nyxstrike_mcp.py \
  --server http://127.0.0.1:8888 \
  --profile full
```

### OpenCode

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "nyxstrike": {
      "type": "local",
      "command": [
        "/path/to/nyxstrike/nyxstrike-env/bin/python3",
        "/path/to/nyxstrike/nyxstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888",
        "--profile",
        "full"
      ],
      "enabled": true
    }
  }
}
```

> Config snippets for Claude Desktop, Cursor, VS Code Copilot, and security options: [Wiki — MCP Setup](https://github.com/CommonHuman-Lab/nyxstrike/wiki/MCP-Setup)

---

## 🔧 Features

NyxStrike does not just run tools — it orchestrates full attack chains using AI decision-making.

- AI agents that chain tools automatically, guided by a decision engine that ranks and re-scores tools mid-scan
- 200+ offensive security tools, all agent-controllable
- Full attack workflow: recon → enumeration → exploitation → reporting
- Local payload & data workbench — 40+ crypto, encoding, and analysis operations, no target required
- Every tool run hash-chained for tamper-evident, verifiable evidence
- Real-time dashboard — live output, network topology maps
- MCP-compatible — plug into any AI client you already use

> [Full feature breakdown](https://github.com/CommonHuman-Lab/nyxstrike/wiki/Features) · [Session & workbench docs](https://github.com/CommonHuman-Lab/nyxstrike/wiki/Dashboard-and-Sessions)

---

## 🧰 Tool Arsenal

200+ offensive security tools across 50+ categories — all dynamically orchestrated by AI agents in real time.

- Network & wireless reconnaissance
- Web & API exploitation
- OSINT & intelligence gathering
- Password & credential attacks
- Binary exploitation & reverse engineering
- Cloud, container & IaC security
- Digital forensics & incident response

> [Full tool list by category](https://github.com/CommonHuman-Lab/nyxstrike/wiki/Tool-Arsenal)

---

## ⚠️ Security Considerations

> NyxStrike gives AI agents direct access to offensive security tooling.

- Run only in isolated environments or dedicated security testing VMs  
- AI agents may execute real commands — maintain operator oversight  
- Monitor activity via dashboard and logs in real time  
- Use `NYXSTRIKE_API_TOKEN` for any non-local deployment

### Legal & Ethical Use

| Allowed | Not Allowed |
|---|---|
| Authorized penetration testing (with written authorization) | Unauthorized testing of any system |
| Bug bounty programs (within program scope and rules) | Malicious, illegal, or harmful activities |
| CTF competitions and educational environments | Unauthorized data access or exfiltration |
| Security research on owned or authorized systems | |
| Red team exercises (with organizational approval) | |

---

## 📜 License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.

---

## ⭐ Support the project

If NyxStrike is useful to your workflow:

- Star the repository
- Share it with others
- Contribute improvements

It makes a real difference.

---

## Credits

Originally inspired by [hexstrike-ai](https://github.com/0x4m4/hexstrike-ai).
