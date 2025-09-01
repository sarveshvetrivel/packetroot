#!/usr/bin/env bash

# =============================================================================
# PacketRoot Installation Script
# Version: 1.0.1
# Author: Sarvesh Vetrivel
# GitHub: https://github.com/sarveshvetrivel/packetroot
# License: Apache 2.0
# Description: Installation script for PacketRoot - PCAP/PCAPNG Forensic & CTF Toolkit
# =============================================================================

# Exit on error, unset variables, and pipeline errors
set -euo pipefail

# Set locale for consistent sorting and text processing
export LC_ALL=C.UTF-8

# Colors and formatting for output - with terminal detection
if [[ -t 1 && -n "${TERM:-}" && "$TERM" != "dumb" ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly PURPLE='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[1;37m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m' # No Color
else
    # No colors if not in terminal or terminal doesn't support colors
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly PURPLE=''
    readonly CYAN=''
    readonly WHITE=''
    readonly BOLD=''
    readonly NC=''
fi

# Constants
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly PACKETROOT_VERSION="1.0.1"
readonly RELEASE_DATE="2025-08-14"
readonly MINIMUM_BASH_VERSION=4.2
readonly MINIMUM_TSHARK_VERSION=3.0.0
readonly INSTALL_PREFIX="/usr/local"
readonly CONFIG_DIR="/etc/packetroot"
readonly LOG_FILE="/var/log/packetroot-install.log"

# Global variables
declare -a MISSING_TOOLS=()
declare -A PACKAGE_MANAGERS=(
    ["debian"]="apt-get"
    ["ubuntu"]="apt-get"
    ["kali"]="apt-get"
    ["arch"]="pacman"
    ["manjaro"]="pacman"
    ["centos"]="yum"
    ["rhel"]="yum"
    ["fedora"]="dnf"
    ["amzn"]="yum"
)

# OS-specific package mappings
declare -A DEBIAN_PACKAGES=(
    [tshark]="tshark"
    [tcpdump]="tcpdump"
    [file]="file"
    [jq]="jq"
    [xxd]="xxd"
    [hashdeep]="hashdeep"
    [grep]="grep"
    [awk]="gawk"
    [sed]="sed"
    [findutils]="findutils"
    [coreutils]="coreutils"
    [curl]="curl"
    [wget]="wget"
    [net-tools]="net-tools"
    [lsof]="lsof"
    [p7zip]="p7zip-full"
    [unzip]="unzip"
    [binwalk]="binwalk"
    [foremost]="foremost"
    [scalpel]="scalpel"
    [yara]="yara"
    [hashcat]="hashcat"
    [ffmpeg]="ffmpeg"
    [exiv2]="exiv2"
    [steghide]="steghide"
    [gnuplot]="gnuplot"
    [graphviz]="graphviz"
    [python3]="python3"
    [python3-pip]="python3-pip"
    [exiftool]="libimage-exiftool-perl"
)

declare -A ARCH_PACKAGES=(
    [tshark]="wireshark-cli"
    [tcpdump]="tcpdump"
    [file]="file"
    [jq]="jq"
    [xxd]="vim"
    [hashdeep]="hashdeep"
    [grep]="grep"
    [awk]="gawk"
    [sed]="sed"
    [findutils]="findutils"
    [coreutils]="coreutils"
    [curl]="curl"
    [wget]="wget"
    [net-tools]="net-tools"
    [lsof]="lsof"
    [p7zip]="p7zip"
    [unzip]="unzip"
    [binwalk]="binwalk"
    [foremost]="foremost"
    [scalpel]="scalpel"
    [yara]="yara"
    [hashcat]="hashcat"
    [ffmpeg]="ffmpeg"
    [exiv2]="exiv2"
    [steghide]="steghide"
    [gnuplot]="gnuplot"
    [graphviz]="graphviz"
    [python3]="python"
    [python3-pip]="python-pip"
    [exiftool]="perl-image-exiftool"
)

declare -A RHEL_PACKAGES=(
    [tshark]="wireshark"
    [tcpdump]="tcpdump"
    [file]="file"
    [jq]="jq"
    [xxd]="vim-common"
    [hashdeep]="hashdeep"
    [grep]="grep"
    [awk]="gawk"
    [sed]="sed"
    [findutils]="findutils"
    [coreutils]="coreutils"
    [curl]="curl"
    [wget]="wget"
    [net-tools]="net-tools"
    [lsof]="lsof"
    [p7zip]="p7zip"
    [unzip]="unzip"
    [binwalk]="binwalk"
    [foremost]="foremost"
    [scalpel]="scalpel"
    [yara]="yara"
    [hashcat]="hashcat"
    [ffmpeg]="ffmpeg"
    [exiv2]="exiv2"
    [steghide]="steghide"
    [gnuplot]="gnuplot"
    [graphviz]="graphviz"
    [python3]="python3"
    [python3-pip]="python3-pip"
    [exiftool]="perl-Image-ExifTool"
)

# Tool categories for different install modes
declare -a MINIMAL_TOOLS=(
    "tshark" "tcpdump" "file" "jq" "xxd" "hashdeep"
    "grep" "awk" "sed" "findutils" "coreutils"
    "curl" "wget" "net-tools" "lsof" "p7zip" "unzip"
)

declare -a FULL_TOOLS=(
    "tshark" "tcpdump" "file" "jq" "xxd" "hashdeep"
    "grep" "awk" "sed" "findutils" "coreutils"
    "curl" "wget" "net-tools" "lsof" "p7zip" "unzip"
    "binwalk" "foremost" "scalpel" "yara" "hashcat"
    "ffmpeg" "exiv2" "steghide" "gnuplot" "graphviz"
    "python3" "python3-pip" "exiftool"
)

# Initialize global state variables
AUTO_CONFIRM=false
CREATE_SHORTCUTS=true
INSTALL_MODE=""
DEBUG=true
setup_steps=0
setup_success=0
start_time=$(date +%s)

# Function to safely create log file
setup_logging() {
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"
    
    # Try to create log directory
    if ! mkdir -p "$log_dir" 2>/dev/null; then
        print_status "WARN" "Cannot create log directory: $log_dir"
        # Use temporary log file
        LOG_FILE="/tmp/packetroot-install-$(date +%s).log"
        print_status "INFO" "Using temporary log file: $LOG_FILE"
    fi
    
    # Test if we can write to log file
    if ! touch "$LOG_FILE" 2>/dev/null; then
        print_status "WARN" "Cannot write to log file: $LOG_FILE"
        LOG_FILE="/dev/null"
    fi
}

# Function to print colored banner with version info
print_banner() {
    local message="$1"
    local color="${2:-$CYAN}"
    local width=80
    
    echo -e "\n${color}$(printf '%*s' $width | tr ' ' '=')${NC}"
    echo -e "${color}  $message${NC}"
    echo -e "${color}  ${WHITE}PacketRoot v${PACKETROOT_VERSION} - Advanced PCAP Analysis Toolkit${NC}"
    echo -e "${color}$(printf '%*s' $width | tr ' ' '=')${NC}\n"
}

# Function to print section headers
print_section() {
    local message="$1"
    echo -e "\n${BOLD}${BLUE}>>> $message${NC}"
}

# Function to print status messages with timestamps
print_status() {
    local status="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$status" in
        "INFO")    echo -e "${BLUE}[${timestamp}] [INFO]${NC} $message" ;;
        "WARN")    echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $message" ;;
        "ERROR")   echo -e "${RED}[${timestamp}] [ERROR]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} $message" ;;
        "PROGRESS") echo -e "${CYAN}[${timestamp}] [+]${NC} $message" ;;
        "DEBUG")   [[ "${DEBUG:-false}" == "true" ]] && echo -e "${WHITE}[${timestamp}] [DEBUG]${NC} $message" ;;
        *)          echo -e "${WHITE}[${timestamp}] [$status]${NC} $message" ;;
    esac
    
    # Log to file (only if we have a valid log file)
    if [[ "$LOG_FILE" != "/dev/null" ]]; then
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] [$status] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Function to confirm actions with user
confirm_continue() {
    local message="$1"
    local default="${2:-n}"
    
    if [[ "$AUTO_CONFIRM" == "true" ]]; then
        return 0
    fi
    
    echo -ne "${YELLOW}$message [y/N]: ${NC}"
    read -r response
    response=${response:-$default}
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to check internet connectivity
check_internet() {
    local hosts=("8.8.8.8" "1.1.1.1")
    
    for host in "${hosts[@]}"; do
        if timeout 5 ping -c 1 -W 3 "$host" &>/dev/null; then
            return 0
        fi
    done
    
    return 1
}

# Function to detect OS and package manager with better error handling
detect_os() {
    local os_id=""
    local os_version=""
    
    print_status "DEBUG" "Detecting operating system..."
    
    # Check for systemd-based systems
    if [[ -f /etc/os-release ]]; then
        print_status "DEBUG" "Found /etc/os-release"
        # Use a safer method to read the file
        while IFS='=' read -r key value; do
            case "$key" in
                ID) os_id="${value//\"/}" ;;
                VERSION_ID) os_version="${value//\"/}" ;;
            esac
        done < /etc/os-release
        
        # Convert to lowercase
        os_id="${os_id,,}"
        
        print_status "DEBUG" "Detected OS ID: $os_id, Version: $os_version"
    # Check for older RedHat-based systems
    elif [[ -f /etc/redhat-release ]]; then
        print_status "DEBUG" "Found /etc/redhat-release"
        if grep -q "CentOS" /etc/redhat-release; then
            os_id="centos"
        elif grep -q "Red Hat" /etc/redhat-release; then
            os_id="rhel"
        fi
        os_version=$(grep -oE '[0-9.]+' /etc/redhat-release | cut -d. -f1 2>/dev/null || echo "")
    # Check for Arch Linux
    elif [[ -f /etc/arch-release ]]; then
        print_status "DEBUG" "Found /etc/arch-release"
        os_id="arch"
    fi
    
    # Fallback to uname if still unknown
    if [[ -z "$os_id" ]]; then
        print_status "DEBUG" "No specific OS files found, using uname fallback"
        os_id=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    
    print_status "DEBUG" "Final OS ID: $os_id"
    
    # Map to supported package managers
    if [[ -n "${PACKAGE_MANAGERS[$os_id]:-}" ]]; then
        print_status "DEBUG" "Found package manager: ${PACKAGE_MANAGERS[$os_id]}"
        echo "$os_id"
    else
        print_status "WARN" "Unsupported OS detected: $os_id $os_version"
        echo "unknown"
    fi
}

# Function to get package name for specific OS
get_package_name() {
    local tool="$1"
    local os="$2"
    
    case "$os" in
        "debian"|"ubuntu"|"kali")
            echo "${DEBIAN_PACKAGES[$tool]:-$tool}"
            ;;
        "arch"|"manjaro")
            echo "${ARCH_PACKAGES[$tool]:-$tool}"
            ;;
        "centos"|"rhel"|'amzn'|"fedora")
            echo "${RHEL_PACKAGES[$tool]:-$tool}"
            ;;
        *)
            echo "$tool"
            ;;
    esac
}

# Function to update package lists with retry logic and better error handling
update_package_lists() {
    local os="$1"
    local max_retries=3
    local retry_delay=5
    local attempt=1
    local success=false
    
    print_status "PROGRESS" "Updating package repositories for OS: $os..."
    
    # Check if package manager is available
    local pkg_manager="${PACKAGE_MANAGERS[$os]:-}"
    if [[ -z "$pkg_manager" ]]; then
        print_status "ERROR" "No package manager found for OS: $os"
        return 1
    fi
    
    if ! command -v "$pkg_manager" &> /dev/null; then
        print_status "ERROR" "Package manager '$pkg_manager' not found in PATH"
        return 1
    fi
    
    while [[ $attempt -le $max_retries && "$success" == "false" ]]; do
        print_status "DEBUG" "Attempt $attempt of $max_retries to update packages for OS: $os"
        
        case "$os" in
            "debian"|"ubuntu"|"kali")
                print_status "DEBUG" "Running: apt-get update -y"
                if timeout 300 apt-get update -y >> "$LOG_FILE" 2>&1; then
                    success=true
                    print_status "DEBUG" "apt-get update succeeded"
                else
                    local exit_code=$?
                    print_status "DEBUG" "apt-get update failed on attempt $attempt (exit code: $exit_code)"
                    
                    # Try to fix common issues
                    if [[ $attempt -eq 1 ]]; then
                        print_status "DEBUG" "Attempting to fix package manager issues..."
                        apt-get clean >> "$LOG_FILE" 2>&1 || true
                        rm -rf /var/lib/apt/lists/* >> "$LOG_FILE" 2>&1 || true
                    fi
                fi
                ;;
            "arch"|"manjaro")
                print_status "DEBUG" "Running: pacman -Sy --noconfirm"
                if timeout 300 pacman -Sy --noconfirm >> "$LOG_FILE" 2>&1; then
                    success=true
                    print_status "DEBUG" "pacman update succeeded"
                else
                    print_status "DEBUG" "pacman update failed on attempt $attempt"
                fi
                ;;
            "centos"|"rhel"|'amzn')
                if command -v dnf &> /dev/null; then
                    print_status "DEBUG" "Running: dnf update -y"
                    if timeout 300 dnf update -y >> "$LOG_FILE" 2>&1; then
                        success=true
                        print_status "DEBUG" "dnf update succeeded"
                    else
                        print_status "DEBUG" "dnf update failed on attempt $attempt"
                    fi
                elif command -v yum &> /dev/null; then
                    print_status "DEBUG" "Running: yum update -y"
                    if timeout 300 yum update -y >> "$LOG_FILE" 2>&1; then
                        success=true
                        print_status "DEBUG" "yum update succeeded"
                    else
                        print_status "DEBUG" "yum update failed on attempt $attempt"
                    fi
                else
                    print_status "ERROR" "No package manager found (dnf/yum) for OS: $os"
                    return 1
                fi
                ;;
            "fedora")
                print_status "DEBUG" "Running: dnf update -y"
                if timeout 300 dnf update -y >> "$LOG_FILE" 2>&1; then
                    success=true
                    print_status "DEBUG" "dnf update succeeded"
                else
                    print_status "DEBUG" "dnf update failed on attempt $attempt"
                fi
                ;;
            *)
                print_status "ERROR" "Unsupported operating system: $os"
                return 1
                ;;
        esac
        
        if [[ "$success" == "false" && $attempt -lt $max_retries ]]; then
            print_status "WARN" "Attempt $attempt failed, retrying in $retry_delay seconds..."
            sleep $retry_delay
            ((attempt++))
        elif [[ "$success" == "false" ]]; then
            print_status "ERROR" "Failed to update package repositories after $max_retries attempts"
            
            # Show last few lines of log for debugging
            if [[ -f "$LOG_FILE" && "$LOG_FILE" != "/dev/null" ]]; then
                print_status "DEBUG" "Last 10 lines from log:"
                tail -10 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
                    print_status "DEBUG" "LOG: $line"
                done
            fi
            return 1
        fi
    done
    
    print_status "SUCCESS" "Package repositories updated successfully"
    return 0
}

# Function to install package with retry logic and better error handling
install_package() {
    local os="$1"
    local tool="$2"
    local max_retries=2
    local attempt=1
    local success=false
    
    # Get the actual package name for this OS
    local pkg
    pkg=$(get_package_name "$tool" "$os")
    
    print_status "PROGRESS" "Installing $tool (package: $pkg)"
    
    # First check if tool is already installed
    if command -v "$tool" &> /dev/null; then
        print_status "INFO" "$tool is already installed, skipping"
        return 0
    fi
    
    while [[ $attempt -le $max_retries && "$success" == "false" ]]; do
        print_status "DEBUG" "Attempt $attempt: Installing $pkg"
        
        case "$os" in
            "debian"|"ubuntu"|"kali")
                if timeout 300 apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1; then
                    success=true
                    print_status "DEBUG" "apt-get install $pkg succeeded"
                else
                    local exit_code=$?
                    print_status "DEBUG" "apt-get install $pkg failed (exit: $exit_code)"
                    
                    # Try alternative package names for some tools
                    if [[ $attempt -eq 1 ]]; then
                        case "$tool" in
                            "exiftool")
                                print_status "DEBUG" "Trying alternative package: exiftool"
                                if timeout 300 apt-get install -y exiftool >> "$LOG_FILE" 2>&1; then
                                    success=true
                                fi
                                ;;
                        esac
                    fi
                fi
                ;;
            "arch"|"manjaro")
                if timeout 300 pacman -S --noconfirm "$pkg" >> "$LOG_FILE" 2>&1; then
                    success=true
                    print_status "DEBUG" "pacman install $pkg succeeded"
                else
                    print_status "DEBUG" "pacman install $pkg failed"
                fi
                ;;
            "centos"|"rhel"|'amzn')
                if command -v dnf &> /dev/null; then
                    if timeout 300 dnf install -y "$pkg" >> "$LOG_FILE" 2>&1; then
                        success=true
                        print_status "DEBUG" "dnf install $pkg succeeded"
                    else
                        print_status "DEBUG" "dnf install $pkg failed"
                    fi
                elif command -v yum &> /dev/null; then
                    if timeout 300 yum install -y "$pkg" >> "$LOG_FILE" 2>&1; then
                        success=true
                        print_status "DEBUG" "yum install $pkg succeeded"
                    else
                        print_status "DEBUG" "yum install $pkg failed"
                    fi
                else
                    print_status "ERROR" "No package manager found for RHEL-based system"
                    return 1
                fi
                ;;
            "fedora")
                if timeout 300 dnf install -y "$pkg" >> "$LOG_FILE" 2>&1; then
                    success=true
                    print_status "DEBUG" "dnf install $pkg succeeded"
                else
                    print_status "DEBUG" "dnf install $pkg failed"
                fi
                ;;
            *)
                print_status "ERROR" "Unsupported operating system: $os"
                return 1
                ;;
        esac
        
        if [[ "$success" == "false" && $attempt -lt $max_retries ]]; then
            print_status "WARN" "Installation of $pkg failed (attempt $attempt), retrying..."
            sleep 3
            ((attempt++))
        elif [[ "$success" == "false" ]]; then
            print_status "ERROR" "Failed to install $pkg after $max_retries attempts"
            MISSING_TOOLS+=("$tool")
            return 1
        fi
    done
    
    # Verify installation
    if command -v "$tool" &> /dev/null; then
        print_status "SUCCESS" "Successfully installed and verified $tool"
        return 0
    else
        print_status "WARN" "Package $pkg installed but command $tool not found in PATH"
        MISSING_TOOLS+=("$tool")
        return 1
    fi
}

# Function to install dependencies based on mode
install_dependencies() {
    local os
    os=$(detect_os)
    
    if [[ "$os" == "unknown" ]]; then
        print_status "ERROR" "Cannot install packages on unsupported OS"
        return 1
    fi
    
    print_status "INFO" "Installing dependencies for mode: $INSTALL_MODE"
    
    # Determine which tools to install
    local tools_to_install=()
    if [[ "$INSTALL_MODE" == "minimal" ]]; then
        tools_to_install=("${MINIMAL_TOOLS[@]}")
    elif [[ "$INSTALL_MODE" == "full" ]]; then
        tools_to_install=("${FULL_TOOLS[@]}")
    else
        print_status "ERROR" "Invalid install mode: $INSTALL_MODE"
        return 1
    fi
    
    # Update package lists first
    if ! update_package_lists "$os"; then
        print_status "ERROR" "Failed to update package lists"
        return 1
    fi
    
    # Install each tool
    local failed_count=0
    local success_count=0
    
    for tool in "${tools_to_install[@]}"; do
        if install_package "$os" "$tool"; then
            ((success_count++))
        else
            ((failed_count++))
        fi
    done
    
    print_status "INFO" "Package installation summary: $success_count successful, $failed_count failed"
    
    # Install Python packages for full mode
    if [[ "$INSTALL_MODE" == "full" && -x "$(command -v pip3)" ]]; then
        print_status "PROGRESS" "Installing Python packages..."
        local python_packages=("scapy" "pylibpcap" "pyshark" "pyyaml")
        
        for py_pkg in "${python_packages[@]}"; do
            if timeout 120 pip3 install --upgrade "$py_pkg" >> "$LOG_FILE" 2>&1; then
                print_status "SUCCESS" "Installed Python package: $py_pkg"
            else
                print_status "WARN" "Failed to install Python package: $py_pkg"
            fi
        done
    fi
    
    # Return success if we installed at least some core tools
    if [[ $success_count -gt 5 ]]; then  # At least 6 core tools installed
        return 0
    else
        print_status "ERROR" "Too many package installations failed ($failed_count failed, $success_count succeeded)"
        return 1
    fi
}

# Function to check if a tool is installed
check_tool() {
    local tool="$1"
    local category="$2"
    local required="$3"
    
    if command -v "$tool" &> /dev/null; then
        print_status "SUCCESS" "[${category}] $tool is installed"
        return 0
    else
        if [[ "$required" == "required" ]]; then
            print_status "ERROR" "[${category}] $tool is MISSING (required)"
            return 1
        else
            print_status "WARN" "[${category}] $tool is not installed (optional)"
            return 0
        fi
    fi
}

# Function to check system requirements
check_requirements() {
    print_status "DEBUG" "Checking system requirements..."
    
    # Check Bash version
    local bash_version
    bash_version=$(bash --version | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1 2>/dev/null || echo "0.0")
    print_status "DEBUG" "Detected Bash version: $bash_version"
    
    if [[ -n "$bash_version" ]] && command -v sort &> /dev/null; then
        if [[ "$(printf "%s\n" "$MINIMUM_BASH_VERSION" "$bash_version" | sort -V | head -n1)" != "$MINIMUM_BASH_VERSION" ]]; then
            print_status "ERROR" "Bash version $MINIMUM_BASH_VERSION or higher is required (found $bash_version)"
            return 1
        fi
    fi
    
    # Check for basic system tools
    local basic_tools=("which" "grep" "awk" "sed")
    local missing_basic=()
    
    for tool in "${basic_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_basic+=("$tool")
        fi
    done
    
    if [[ ${#missing_basic[@]} -gt 0 ]]; then
        print_status "ERROR" "Missing basic system tools: ${missing_basic[*]}"
        return 1
    fi
    
    print_status "SUCCESS" "System requirements check passed"
    return 0
}

# Function to verify installations
verify_installations() {
    local missing=0
    local warnings=0
    
    print_banner "Verifying Installations" "$BLUE"
    
    # Core tools that are required for minimal install
    declare -a core_tools=(
        "tshark" "tcpdump" "file" "grep" "awk" "sed"
    )
    
    # Check core tools
    print_status "INFO" "Checking core tools..."
    for tool in "${core_tools[@]}"; do
        if ! check_tool "$tool" "CORE" "required"; then
            ((missing++))
        fi
    done
    
    # Additional tools based on install mode
    if [[ "$INSTALL_MODE" == "full" ]]; then
        declare -a additional_tools=(
            "jq" "xxd" "hashdeep" "curl" "wget" "binwalk" "python3"
        )
        
        print_status "INFO" "Checking additional tools..."
        for tool in "${additional_tools[@]}"; do
            if ! check_tool "$tool" "FULL" "optional"; then
                ((warnings++))
            fi
        done
    fi
    
    # Check Python modules if Python is available
    if command -v python3 &> /dev/null && [[ "$INSTALL_MODE" == "full" ]]; then
        print_status "INFO" "Checking Python modules..."
        declare -a py_modules=("scapy")
        
        for module in "${py_modules[@]}"; do
            if python3 -c "import $module" &> /dev/null 2>&1; then
                print_status "SUCCESS" "[PY] $module is installed"
            else
                print_status "WARN" "[PY] $module is MISSING"
                ((warnings++))
            fi
        done
    fi
    
    # Summary
    echo -e "\n${GREEN}=== Verification Summary ===${NC}"
    echo -e "Core Tools: ${#core_tools[@]} checked, $missing missing"
    
    if [[ "$INSTALL_MODE" == "full" ]]; then
        echo -e "Additional Tools: checked, $warnings missing/recommended"
    fi
    
    if [[ $missing -gt 0 ]]; then
        print_status "ERROR" "Installation incomplete: $missing core tools are missing"
        print_status "INFO" "Missing tools can be installed manually or try running the script again"
        return 1
    elif [[ $warnings -gt 0 ]]; then
        print_status "WARN" "Installation complete with $warnings warnings (optional tools missing)"
        return 0
    else
        print_status "SUCCESS" "All required tools are installed successfully!"
        return 0
    fi
}

# Function to set up Wireshark permissions and capabilities
setup_wireshark() {
    print_banner "Configuring Wireshark Permissions" "$BLUE"
    local changes_made=false
    
    # Check if we're running as root
    if [[ $EUID -ne 0 ]]; then
        print_status "WARN" "Skipping Wireshark setup - requires root privileges"
        return 1
    fi
    
    # Check if Wireshark tools are installed
    if ! command -v tshark &> /dev/null; then
        print_status "WARN" "Wireshark tools not found, skipping configuration"
        return 1
    fi
    
    # 1. Add user to wireshark group
    if command -v usermod &> /dev/null && command -v getent &> /dev/null; then
        local wireshark_group="wireshark"
        
        # Check if wireshark group exists
        if getent group "$wireshark_group" &> /dev/null; then
            # Get the current user (who invoked sudo)
            local current_user="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"
            
            # Add user to wireshark group if not already a member
            if ! id -nG "$current_user" 2>/dev/null | grep -qw "$wireshark_group"; then
                if usermod -aG "$wireshark_group" "$current_user" 2>> "$LOG_FILE"; then
                    print_status "SUCCESS" "Added user '$current_user' to '$wireshark_group' group"
                    changes_made=true
                else
                    print_status "ERROR" "Failed to add user to '$wireshark_group' group"
                fi
            else
                print_status "INFO" "User '$current_user' is already in '$wireshark_group' group"
            fi
        else
            print_status "WARN" "Wireshark group not found. Is Wireshark installed?"
        fi
    else
        print_status "WARN" "Missing required commands for user/group management"
    fi
    
    # 2. Set capabilities for dumpcap
    if command -v setcap &> /dev/null && command -v getcap &> /dev/null; then
        local dumpcap_paths=(
            "/usr/bin/dumpcap"
            "/usr/sbin/dumpcap"
        )
        
        # Add dynamic path if dumpcap is found
        if command -v dumpcap &> /dev/null; then
            dumpcap_paths+=("$(which dumpcap 2>/dev/null)")
        fi
        
        local dumpcap_found=""
        for path in "${dumpcap_paths[@]}"; do
            if [[ -x "$path" ]]; then
                dumpcap_found="$path"
                break
            fi
        done
        
        if [[ -n "$dumpcap_found" ]]; then
            # Check if capabilities are already set
            if ! getcap "$dumpcap_found" 2>/dev/null | grep -q cap_net_raw; then
                if setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "$dumpcap_found" 2>> "$LOG_FILE"; then
                    print_status "SUCCESS" "Set network capture capabilities for dumpcap"
                    changes_made=true
                    
                    # Verify the capabilities were set
                    if ! getcap "$dumpcap_found" 2>/dev/null | grep -q cap_net_raw; then
                        print_status "WARN" "Failed to verify dumpcap capabilities - may need manual setup"
                    fi
                else
                    print_status "ERROR" "Failed to set dumpcap capabilities (tried: $dumpcap_found)"
                fi
            else
                print_status "INFO" "Dumpcap already has required capabilities"
            fi
        else
            print_status "WARN" "Could not find dumpcap executable"
        fi
    else
        print_status "WARN" "Missing setcap/getcap utilities - cannot set dumpcap capabilities"
    fi
    
    if [[ "$changes_made" == "true" ]]; then
        print_status "INFO" "You may need to log out and back in for all changes to take effect"
    else
        print_status "INFO" "No changes were needed - Wireshark is properly configured"
    fi
    
    return 0
}

# Function to create desktop and application menu shortcuts
create_shortcuts() {
    print_banner "Creating Application Shortcuts" "$BLUE"
    local shortcuts_created=0
    
    # Find the script's icon (use Wireshark icon or default to system icon)
    local icon_path=""
    local icon_paths=(
        "/usr/share/icons/hicolor/48x48/apps/wireshark.png"
        "/usr/share/pixmaps/wireshark.xpm"
        "/usr/share/icons/gnome/48x48/apps/utilities-terminal.png"
        "utilities-terminal"  # Fallback to system terminal icon
    )
    
    for path in "${icon_paths[@]}"; do
        if [[ -f "$path" || "$path" == "utilities-terminal" ]]; then
            icon_path="$path"
            break
        fi
    done
    
    # Get the absolute path to the script
    local script_path="$SCRIPT_DIR/packetroot.sh"
    
    # Check if packetroot.sh exists
    if [[ ! -f "$script_path" ]]; then
        print_status "WARN" "Main script not found at $script_path, skipping shortcuts"
        return 1
    fi
    
    # 1. Create desktop shortcut
    local desktop_dirs=(
        "$HOME/Desktop"
        "$HOME/desktop"  # Some systems use lowercase
    )
    
    for dir in "${desktop_dirs[@]}"; do
        if [[ -d "$dir" && -w "$dir" ]]; then
            cat > "$dir/packetroot.desktop" <<EOL
[Desktop Entry]
Version=1.0
Type=Application
Name=PacketRoot
GenericName=PCAP Analysis Tool
Comment=Advanced network capture analysis toolkit
Exec=gnome-terminal -- bash -c "cd '$SCRIPT_DIR' && ./packetroot.sh; exec bash"
Icon=$icon_path
Terminal=true
Categories=Network;Analysis;Security;
Keywords=network;security;forensics;pcap;analysis;
StartupNotify=true
EOL
            
            chmod +x "$dir/packetroot.desktop" 2>/dev/null || true
            print_status "SUCCESS" "Created desktop shortcut in $dir/"
            ((shortcuts_created++))
            break  # Only create in the first writable directory found
        fi
    done
    
    # 2. Create application menu shortcut
    local app_dirs=(
        "$HOME/.local/share/applications"
        "/usr/local/share/applications"
        "/usr/share/applications"
    )
    
    for dir in "${app_dirs[@]}"; do
        if [[ -d "$dir" && ( -w "$dir" || $EUID -eq 0 ) ]]; then
            # Use sudo if we don't have write permissions but are root
            local sudo_cmd=""
            [[ ! -w "$dir" && $EUID -eq 0 ]] && sudo_cmd="sudo "
            
            ${sudo_cmd}cat > "$dir/packetroot.desktop" <<EOL
[Desktop Entry]
Version=1.0
Type=Application
Name=PacketRoot
GenericName=PCAP Analysis Tool
Comment=Advanced network capture analysis toolkit
Exec=$script_path %f
Icon=$icon_path
Terminal=true
Categories=Network;Analysis;Security;Utility;
Keywords=network;security;forensics;pcap;analysis;
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;application/x-pcap;
StartupNotify=true
EOL
            
            ${sudo_cmd}chmod +x "$dir/packetroot.desktop" 2>/dev/null || true
            
            # Update desktop database if we're in a system directory
            if [[ "$dir" == "/usr"* ]] && command -v update-desktop-database &> /dev/null; then
                ${sudo_cmd}update-desktop-database -q "$dir" 2>/dev/null || true
            fi
            
            print_status "SUCCESS" "Created application menu shortcut in $dir/"
            ((shortcuts_created++))
            break  # Only create in the first writable directory found
        fi
    done
    
    if [[ $shortcuts_created -eq 0 ]]; then
        print_status "WARN" "Could not create any shortcuts. No writable directories found."
        return 1
    else
        print_status "SUCCESS" "Created $shortcuts_created shortcut(s)"
        return 0
    fi
}

# Function to show help information
show_help() {
    cat << EOF
PacketRoot Installation Script v${PACKETROOT_VERSION}

DESCRIPTION:
    Installation script for PacketRoot - Advanced PCAP/PCAPNG Forensic & CTF Toolkit

USAGE:
    sudo $0 [OPTIONS] <MODE>

MODES:
    minimal    Install core tools only (tshark, tcpdump, file, etc.)
    full       Install all tools including advanced analysis tools

OPTIONS:
    -h, --help          Show this help message
    -y, --yes           Auto-confirm all prompts
    --no-shortcuts      Skip creating desktop/menu shortcuts
    --minimal           Set installation mode to minimal
    --full              Set installation mode to full
    --debug             Enable debug output

EXAMPLES:
    sudo $0 minimal
    sudo $0 full --yes
    sudo $0 --minimal --no-shortcuts

SUPPORTED SYSTEMS:
    - Debian/Ubuntu/Kali (apt-get)
    - Arch Linux/Manjaro (pacman)
    - RedHat/CentOS/Fedora (yum/dnf)
    - Amazon Linux (yum)

REQUIREMENTS:
    - Root privileges (use sudo)
    - Internet connection
    - Bash ${MINIMUM_BASH_VERSION}+ 

FILES CREATED:
    - Log file: $LOG_FILE
    - Desktop shortcuts (optional)
    - Application menu entries (optional)

NOTE:
    This script must be run with root privileges using sudo
EOF
}

# Function to display usage (simplified version)
usage() {
    cat << EOF
PacketRoot Installation Script

USAGE:
    sudo $0 <mode> [options]

MODES:
    minimal    Install core tools (tshark, tcpdump, file, etc.)
    full       Install all tools including advanced analysis tools

OPTIONS:
    -h, --help       Show detailed help
    -y, --yes        Auto-confirm all prompts
    --no-shortcuts   Skip creating shortcuts
    --debug          Enable debug output

EXAMPLES:
    sudo $0 minimal
    sudo $0 full --yes

SUPPORTED SYSTEMS:
    - Debian/Ubuntu/Kali (apt)
    - Arch Linux (pacman)
    - RedHat/CentOS/Fedora (yum/dnf)

NOTE: This script must be run with root privileges (sudo)
EOF
}

# Function to handle cleanup on exit
cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        print_status "ERROR" "Installation failed with exit code $exit_code"
        print_status "INFO" "Check log file for details: $LOG_FILE"
        
        # Show recent log entries for debugging
        if [[ -f "$LOG_FILE" && "$LOG_FILE" != "/dev/null" ]]; then
            echo -e "\n${YELLOW}Last 15 lines from log file:${NC}"
            tail -15 "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
                echo "  $line"
            done
        fi
        
        echo -e "\n${YELLOW}Troubleshooting tips:${NC}"
        echo "1. Make sure you have internet connectivity"
        echo "2. Try running: sudo apt-get update (for Debian/Ubuntu systems)"
        echo "3. Check if your package manager is working properly"
        echo "4. Try running the script again with --debug flag"
    fi
}

# Function to handle errors with context
handle_error() {
    local line_number="$1"
    local command="$2"
    local exit_code="$3"
    
    print_status "ERROR" "Script failed at line $line_number"
    print_status "ERROR" "Failed command: $command"
    print_status "ERROR" "Exit code: $exit_code"
    
    # Provide context-specific error messages
    case "$command" in
        *"apt-get"*|*"pacman"*|*"yum"*|*"dnf"*)
            print_status "ERROR" "Package manager command failed. Check internet connection and repository configuration."
            ;;
        *"install_dependencies"*)
            print_status "ERROR" "Dependency installation failed. Some packages may not be available."
            ;;
        *"update_package_lists"*)
            print_status "ERROR" "Failed to update package repositories. Check network connectivity."
            ;;
    esac
}

# Set up error handling
set -E
trap 'handle_error ${LINENO} "$BASH_COMMAND" $?' ERR
trap cleanup EXIT

# Main function
main() {
    # Initialize timing
    start_time=$(date +%s)
    
    # Set up logging first
    setup_logging
    
    # Start logging
    print_status "INFO" "Starting PacketRoot installation script v$PACKETROOT_VERSION"
    print_status "INFO" "Command: $0 $*"
    print_status "INFO" "User: $(whoami)"
    print_status "INFO" "Date: $(date)"
    print_status "INFO" "PID: $"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -y|--yes)
                AUTO_CONFIRM=true
                shift
                ;;
            --no-shortcuts)
                CREATE_SHORTCUTS=false
                shift
                ;;
            --debug)
                DEBUG=true
                set -x  # Enable bash debugging
                shift
                ;;
            --minimal)
                INSTALL_MODE="minimal"
                shift
                ;;
            --full)
                INSTALL_MODE="full"
                shift
                ;;
            minimal|full)
                INSTALL_MODE="$1"
                shift
                ;;
            *)
                print_status "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate install mode
    if [[ -z "$INSTALL_MODE" ]]; then
        print_status "ERROR" "No installation mode specified"
        usage
        exit 1
    fi
    
    if [[ "$INSTALL_MODE" != "minimal" && "$INSTALL_MODE" != "full" ]]; then
        print_status "ERROR" "Invalid installation mode: $INSTALL_MODE"
        usage
        exit 1
    fi
    
    # Show welcome message
    print_banner "PacketRoot Installation" "$GREEN"
    print_status "INFO" "Starting PacketRoot installation (Mode: ${INSTALL_MODE^})"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "This script must be run as root. Please use 'sudo $0 $INSTALL_MODE'"
        exit 1
    fi
    
    # Check system requirements first
    print_section "Checking System Requirements"
    setup_steps=$((setup_steps + 1))
    if check_requirements; then
        setup_success=$((setup_success + 1))
        print_status "SUCCESS" "System requirements check passed"
    else
        print_status "ERROR" "System requirements check failed"
        exit 1
    fi
    
    # Check for internet connectivity
    print_section "Checking Internet Connectivity"
    if check_internet; then
        print_status "SUCCESS" "Internet connectivity verified"
    else
        print_status "WARN" "No internet connection detected. Some features may be limited."
        if ! confirm_continue "Continue with installation without internet?" "n"; then
            exit 1
        fi
    fi
    
    # Detect OS
    print_section "Detecting Operating System"
    local detected_os
    detected_os=$(detect_os)
    if [[ "$detected_os" == "unknown" ]]; then
        print_status "ERROR" "Unsupported operating system detected"
        print_status "INFO" "Supported systems: Debian, Ubuntu, Kali, Arch, Manjaro, CentOS, RHEL, Fedora"
        exit 1
    fi
    print_status "SUCCESS" "Detected OS: $detected_os"
    
    # 1. System preparation
    print_section "System Preparation"
    ((setup_steps++))
    if update_package_lists "$detected_os"; then
        ((setup_success++))
    else
        print_status "WARN" "Failed to update package lists, but continuing..."
        # Don't exit here, try to continue
    fi
    
    # 2. Install dependencies
    print_section "Installing Dependencies"
    ((setup_steps++))
    if install_dependencies; then
        ((setup_success++))
    else
        print_status "ERROR" "Failed to install some dependencies"
        if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
            print_status "INFO" "Missing tools: ${MISSING_TOOLS[*]}"
        fi
        
        if ! confirm_continue "Continue with installation despite missing tools?" "y"; then
            exit 1
        fi
    fi
    
    # 3. Setup Wireshark (non-critical)
    print_section "Configuring Wireshark"
    ((setup_steps++))
    if setup_wireshark; then
        ((setup_success++))
    else
        print_status "WARN" "Wireshark setup had some issues (non-critical)"
        ((setup_success++))  # Don't count this as a failure
    fi
    
    # 4. Create shortcuts if enabled (non-critical)
    if [[ "$CREATE_SHORTCUTS" == "true" ]]; then
        print_section "Creating Application Shortcuts"
        ((setup_steps++))
        if create_shortcuts; then
            ((setup_success++))
        else
            print_status "WARN" "Some shortcuts could not be created (non-critical)"
            ((setup_success++))  # Don't count this as a failure
        fi
    fi
    
    # 5. Final verification
    print_section "Verifying Installation"
    ((setup_steps++))
    local verification_result=0
    if verify_installations; then
        ((setup_success++))
        verification_result=0
    else
        print_status "WARN" "Some verification checks failed"
        verification_result=1
    fi
    
    # Calculate installation time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Show summary
    print_banner "Installation Summary" "$GREEN"
    echo -e "${WHITE}Steps Completed:${NC} $setup_success/$setup_steps"
    echo -e "${WHITE}Time Elapsed:${NC}   ${duration} seconds"
    echo -e "${WHITE}Log File:${NC}       $LOG_FILE"
    echo -e "${WHITE}Install Mode:${NC}   ${INSTALL_MODE^}"
    
    if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
        echo -e "${WHITE}Missing Tools:${NC}   ${MISSING_TOOLS[*]}"
    fi
    
    # Determine overall success
    local min_success_rate=4  # At least 4 out of 5 steps should succeed
    if [[ $setup_success -ge $min_success_rate && $verification_result -eq 0 ]]; then
        print_banner "Installation Complete!" "$GREEN"
        print_status "SUCCESS" "PacketRoot has been successfully installed."
        echo -e "\n${WHITE}Next Steps:${NC}"
        echo -e "1. Open a new terminal or run: ${CYAN}source ~/.bashrc${NC}"
        echo -e "2. Start analyzing PCAP files: ${CYAN}./packetroot.sh -h${NC} (for help)"
        
        if [[ "$CREATE_SHORTCUTS" == "true" ]]; then
            echo -e "3. Find PacketRoot in your applications menu or desktop"
        fi
        
        # Show important notes
        echo -e "\n${YELLOW}Important Notes:${NC}"
        echo -e "- You may need to log out and back in for all changes to take effect"
        echo -e "- For help with PacketRoot usage, run: ${CYAN}./packetroot.sh --help${NC}"
        echo -e "- Log file location: ${CYAN}$LOG_FILE${NC}"
        
        return 0
    else
        print_banner "Installation Partially Complete" "$YELLOW"
        print_status "WARN" "Some installation steps did not complete successfully."
        echo -e "\n${YELLOW}Troubleshooting:${NC}"
        echo "1. Check the log file for errors: ${CYAN}$LOG_FILE${NC}"
        echo "2. Make sure your system meets all requirements"
        echo "3. Check internet connectivity: ping 8.8.8.8"
        echo "4. Try running the installation again with: ${CYAN}sudo $0 $INSTALL_MODE --debug${NC}"
        echo -e "\n${WHITE}You can still try running PacketRoot, but some features may not work.${NC}"
        
        return 1
    fi
}

# Script entry point with better error handling
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    
    # Check if no arguments provided
    if [[ $# -eq 0 ]]; then
        echo -e "${RED}Error: No installation mode specified${NC}"
        echo
        usage
        exit 1
    fi
    
    # Handle help first (before any other processing)
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            show_help
            exit 0
        fi
    done
    
    # Check if we have a valid mode somewhere in the arguments
    has_mode=false  # ← Fixed: removed 'local'
    for arg in "$@"; do
        if [[ "$arg" == "minimal" || "$arg" == "full" || "$arg" == "--minimal" || "$arg" == "--full" ]]; then
            has_mode=true
            break
        fi
    done
    
    if [[ "$has_mode" == "false" ]]; then
        echo -e "${RED}Error: No valid installation mode found${NC}"
        echo -e "${YELLOW}Valid modes: minimal, full${NC}"
        echo
        usage
        exit 1
    fi
    
    # Run the main function with all arguments
    main "$@"
fi

