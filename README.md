PacketRoot is a powerful, open-source toolkit designed for comprehensive
forensic analysis of PCAP/PCAPNG files. Built with security researchers,
network analysts, and CTF players in mind, it combines multiple analysis
tools into a single, streamlined interface with powerful automation
capabilities.

## 🚀 Quick Start

### Prerequisites

-   Linux (Ubuntu/Debian, CentOS/RHEL, or Arch Linux recommended)
-   Bash 4.2 or higher
-   Root/sudo access for installation

### Installation

``` bash
# Clone the repository
git clone https://github.com/sarveshvetrivel/packetroot.git
cd packetroot

# Install dependencies (requires sudo)
sudo ./install.sh --full

```

### Basic Usage

``` bash
# Basic analysis
./packetroot.sh capture.pcap

# Quick analysis (metadata only)
./packetroot.sh --quick capture.pcap

# CTF mode with flag pattern
./packetroot.sh --ctf "FLAG{" ctf_challenge.pcap

# Deep analysis (all modules)
./packetroot.sh --deep forensic_capture.pcap
```

## ✨ Why PacketRoot?

-   **All-in-One Solution**: Combines multiple network analysis tools
    into a single workflow
-   **CTF Optimized**: Built-in support for common CTF challenges and
    flag formats
-   **Comprehensive Analysis**: From basic metadata to advanced protocol
    analysis
-   **User-Friendly**: Color-coded output and intuitive interface
-   **Extensible**: Easily add custom analysis modules and scripts

## 🔍 Key Features

### 🌐 Traffic Analysis

-   **Protocol Analysis**
    -   Complete protocol hierarchy and distribution
    -   Top talkers and conversations (IP/MAC)
    -   Port scanning and suspicious activity detection
    -   DNS query/response correlation
    -   HTTP/HTTPS transaction analysis
    -   SSL/TLS certificate inspection and validation
-   **Advanced Traffic Analysis**
    -   GeoIP mapping of IP addresses
    -   Bandwidth usage and throughput analysis
    -   Flow reconstruction and analysis
-   **Security & Forensics**
    -   Suspicious pattern detection
    -   Known IOCs (Indicators of Compromise) matching
    -   Anomaly detection in network behavior
    -   Credential hunting in plaintext protocols
    -   Malware traffic pattern identification
-   **CTF & Investigation Tools**
    -   Custom keyword/flag pattern matching
    -   File carving with multiple tools (binwalk, foremost, scalpel)
    -   Steganography detection in images and network streams
    -   Timeline generation of network events
    -   Extracted file analysis and classification

### 🏆 CTF Features

-   **Keyword Search**: Hunt for CTF flags across extracted data
-   **Stream Analysis**: Reassemble and analyze network streams
-   **File Recovery**: Extract embedded files from network traffic
-   **Timeline Generation**: Create chronological event timeline

## 🛠 Installation

### Installation Options

#### 1. Full Installation (Recommended)

``` bash
# Clone the repository
git clone https://github.com/sarveshvetrivel/packetroot.git
cd packetroot

# Run the installation script (interactive)
sudo ./install.sh

```

#### 2. Minimal Installation (Lightweight)

``` bash
# Install only essential dependencies
sudo ./install.sh --minimal
```

#### 3. Install Specific Components

``` bash
# Install only core analysis tools
sudo ./install.sh --core

# Install CTF-specific tools
sudo ./install.sh --ctf

# Install forensics tools
sudo ./install.sh --forensics
```

### Post-Installation

After installation, you may need to log out and back in for Wireshark
permissions to take effect. To verify your installation:

``` bash
./packetroot.sh --version
./packetroot.sh --check-tools
```

### Updating PacketRoot

``` bash
cd /path/to/packetroot
git pull
sudo ./install.sh --update
```

#### Optional Dependencies (Recommended for Full Functionality)

-   **File Carving & Analysis**
    -   `binwalk` - Advanced file carving
    -   `foremost` - File recovery
    -   `scalpel` - File carving alternative
    -   `exiftool` - Metadata extraction
    -   `p7zip` - Archive extraction
-   **Security & Forensics**
    -   `zeek` (formerly Bro) - Network analysis framework
    -   `suricata` - Intrusion detection
    -   `yara` - Pattern matching
    -   `hashcat` - Password cracking
-   **Media & Steganography**
    -   `steghide` - Steganography detection
    -   `stegsolve` - Image analysis
    -   `exiv2` - Image metadata
    -   `ffmpeg` - Media analysis
-   **Visualization**
    -   `gnuplot` - Graph generation
    -   `graphviz` - Network diagrams
    -   `python3-matplotlib` - Data visualization

## 💻 Usage

### Basic Analysis

``` bash
# Basic analysis with default options
./packetroot.sh capture.pcap

# Quick analysis (metadata and basic stats only)
./packetroot.sh --quick capture.pcap

# Deep analysis with all modules
./packetroot.sh --deep capture.pcap

# Specify output directory
./packetroot.sh -o ./analysis_results capture.pcap
```


#### 2. CTF Challenge

``` bash
# Search for common CTF flags and hidden data
packetroot.sh --ctf \
    --pattern 'flag{.*}|CTF{.*}|picoCTF{.*}' \
    --carve \
    --stegano \
    ctf_challenge.pcap
```


## 🤝 Contributing

We welcome contributions from the community! Whether you're a developer,
security researcher, or just passionate about network forensics, there
are many ways to contribute.

### How to Contribute

1.  **Report Issues**
    -   Check existing issues before creating a new one
    -   Provide detailed reproduction steps
    -   Include sample PCAPs when possible (sanitized if needed)
2.  **Submit Pull Requests**
    -   Fork the repository and create a feature branch
    -   Follow the existing code style and conventions
    -   Include tests for new functionality
    -   Update documentation as needed
    -   Submit a pull request with a clear description
3.  **Enhance Documentation**
    -   Improve existing documentation
    -   Add usage examples
    -   Translate documentation to other languages

### Pull Request Process

1.  Fork the repository
2.  Create a feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -am 'Add some amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request


### Core Dependencies

-   [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
-   [TShark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html) -
    CLI network protocol analyzer
-   [Scapy](https://scapy.net/) - Packet manipulation library
-   [PyShark](https://github.com/KimiNewt/pyshark) - Python wrapper for
    TShark
-   [YARA](https://virustotal.github.io/yara/) - Pattern matching tool
-   [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis
    tool

### Community & Support

Special thanks to all contributors, testers, and community members who
have helped improve PacketRoot.


## 📊 Output Structure

PacketRoot organizes analysis results in a structured directory format:

    output/
    ├── capture_20230815_143022/       # Timestamped analysis directory
    │   ├── reports/                   # Analysis reports and statistics
    │   │   ├── summary.txt           # Executive summary
    │   │   ├── traffic_analysis.txt   # Traffic analysis
    │   │   ├── protocol_stats.json    # Protocol distribution
    │   │   └── security_findings.txt  # Security-related findings
    │   │
    │   ├── protocols/                 # Protocol-specific extractions
    │   │   ├── http/                  # HTTP requests/responses
    │   │   │   ├── requests/         # Individual HTTP requests
    │   │   │   └── responses/        # Individual HTTP responses
    │   │   ├── dns/                  # DNS queries/responses
    │   │   └── tls/                  # TLS/SSL certificates
    │   │
    │   ├── extracted/                # Extracted files and objects
    │   │   ├── http_objects/         # Files from HTTP traffic
    │   │   ├── dns_objects/          # Files from DNS exfiltration
    │   │   └── carved_files/         # Files carved from raw traffic
    │   │
    │   ├── streams/                  # Reassembled network streams
    │   │   ├── tcp/                  # TCP streams
    │   │   └── udp/                  # UDP streams
    │   │
    │   ├── logs/                     # Tool-specific log files
    │   ├── timeline/                 # Timeline analysis
    │   └── index.html                # HTML report (if generated)


## 📜 License

PacketRoot is licensed under the Apache License 2.0 - see the
[LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

-   TShark and Wireshark for powerful packet analysis
-   Zeek (formerly Bro) for network security monitoring
-   The open-source community for valuable tools and libraries

## 📚 Resources

### Related Projects

-   [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) -
    Network Forensic Analysis Tool
-   [Xplico](https://www.xplico.org/) - Network Forensic Analysis Tool
-   [Moloch](https://github.com/aol/moloch) - Large scale IPv4 packet
    capturing
-   [Zeek](https://zeek.org/) - Network analysis framework

### Learning Resources

-   [Wireshark University](https://www.wireshark.org/learn/)
-   [PacketTotal](https://packettotal.com/) - PCAP analysis in the cloud
-   [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) -
    PCAP exercises and
    challenges\](https://www.wireshark.org/docs/wsug_html_chunked/)
