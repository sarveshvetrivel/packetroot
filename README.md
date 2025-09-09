# PCAP/PCAPNG Forensic & CTF Analysis Toolkit

A comprehensive command-line utility for packet capture analysis, forensic investigation, and CTF challenges. Designed for security professionals, CTF players, and digital forensics experts.

## Key Features

- **Comprehensive Analysis**: Single-command analysis of PCAP/PCAPNG files
- **Interactive Mode**: Guided menu (`-i`) for beginners and CTF players
- **Smart Dependency Checks**: Verifies required tools, warns on optional ones
- **Clear Status Output**: Color-coded console messages (INFO, WARN, ERROR, SUCCESS)
- **Extended Reports**: Enhanced summary with protocol stats, warnings, extracted files, CTF hits, timeline events, and streams
- **Automated Workflow**: Automated multi-phase analysis pipeline
- **Modular Design**: Each module can be run individually or as part of the full workflow
- **Cross-Platform**: Works on Linux and macOS (with some limitations on Windows via WSL)
- **Security-Focused**: Built with strict shell practices and safe execution in mind

## Core Capabilities

### Metadata & File Information
- File metadata extraction with `capinfos`
- Magic number and MIME type identification

### Protocol & Traffic Analysis
- I/O statistics
- Protocol hierarchy
- Endpoints (IP, TCP, UDP)
- Conversations (IP, TCP, UDP)
- ARP, ICMP, DNS, HTTP, TLS, FTP, SMTP, SMB statistics

### Security & IDS Analysis
- Zeek logs (if available)
- Suricata alerts (if available)
- Anomaly and suspicious traffic indicators

### File Carving & Object Extraction
- Data carving with `foremost` and `binwalk`
- Export protocol objects (HTTP, DNS, TLS, FTP, SMTP, SMB)
- Reassembly of TCP/UDP streams

### CTF & Investigation Tools
- Keyword/flag search across payloads (`-c <pattern>`)
- Organized results saved under `ctf/`

### Timeline Analysis
- Always generates a chronological timeline of packets
- Output saved in `timeline/events.txt`

### Extended Analyses
- ICMP analysis
- VoIP analysis (SIP, RTP)
- Entropy analysis

## Core Analysis Tools

- `tshark` – Protocol and traffic analysis
- `capinfos` – File metadata
- `editcap` – Packet trimming
- `foremost` – File carving and recovery
- `binwalk` – Binary carving and embedded data extraction
- `zeek` – IDS and protocol analysis
- `suricata` – IDS and anomaly detection
- `yara` – Pattern and malware rule matching
- `strings` – Text extraction
- `xxd` – Hexadecimal dump
- `file` – File type identification

Each tool is carefully integrated to maximize forensic insight and capture hidden data in network traffic.

## Installation

### Prerequisites
- Linux or macOS (Windows via WSL)
- Git
- `sudo` privileges for installing dependencies

### Step-by-Step Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/yourproject.git
   cd yourproject
   ```

2. **Make the script executable**:
   ```bash
   chmod +x source.sh install_requirements.sh
   ```

3. **Install dependencies**:
   ```bash
   sudo ./install_requirements.sh
   ```

### Post-Installation

Optionally add to PATH:
```bash
echo 'export PATH="$PATH:'$(pwd)'"' >> ~/.bashrc
source ~/.bashrc
```

## 🛠️ Usage Guide

### Basic Usage

Analyze a capture file with default settings:
```bash
./source.sh capture.pcap
```

Example:
```bash
./source.sh network-dump.pcapng
```

### Command-Line Options

```
Usage: ./source.sh [OPTIONS] <file>

Options:
  -q, --quick        Quick analysis (metadata + traffic stats)
  -d, --deep         Deep analysis (all modules)
  -c, --ctf PATTERN  Search for flag/keyword patterns (saved in ctf/)
  -o, --output DIR   Specify custom output directory
  -i, --interactive  Interactive guided menu
  -parallel          Run certain analyses in parallel
  -config FILE       Use custom configuration file
  -h, --help         Show this help message
```

### Interactive Mode

Start guided analysis with:
```bash
./source.sh -i file.pcap
```

**Example Menu:**
```
===== Interactive Analysis Menu =====
1) Metadata Analysis
2) Protocol Statistics
3) Protocol Extraction
4) Security Findings (Zeek/Suricata)
5) File Carving
6) Stream Extraction
7) ICMP Analysis
8) VoIP Analysis
9) Entropy Analysis
10) CTF / Keyword Search
11) Run All Modules
12) View Summary
0) Exit
```

Features of interactive mode:
- Run specific modules individually
- Execute the full pipeline in one step
- On-demand summary view
- Skip, retry, or repeat analyses without restarting

## Output Structure

The tool creates an organized directory for each session:

```
output/
└── capture_YYYYMMDD_HHMMSS/
    ├── reports/
    │   ├── summary.txt
    │   ├── protocol_hierarchy.txt
    │   ├── ip_endpoints.txt
    │   └── traffic_stats.txt
    │
    ├── protocols/
    │   ├── http/
    │   ├── dns/
    │   └── tls/
    │
    ├── carved/
    │   ├── binwalk/
    │   └── foremost/
    │
    ├── streams/
    │   ├── tcp/
    │   └── udp/
    │
    ├── timeline/
    │   └── events.txt
    │
    ├── ctf/   (only if CTF search is run)
    │   └── ctf_search_results.txt
    │
    └── index.md
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please follow these guidelines:

1. Fork and clone:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Development:
   - Use `shellcheck` for code quality
   - Follow POSIX shell best practices
   - Add error handling and comments
   - Test with various PCAP/PCAPNG files
   - Update docs as needed

3. Submit changes:
   ```bash
   git commit -m "feat: add new analysis module"
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request with clear details.

## Security

To report security vulnerabilities:

1. **DO NOT** open public issues for security vulnerabilities
2. Email the maintainers directly
3. Include detailed descriptions and steps to reproduce
4. We will respond within 48 hours with next steps

## Support

For issues, requests, or questions:
1. Check the [Issues](https://github.com/yourusername/yourproject/issues) page
2. Open a new issue with details
3. Follow the issue template guidelines
