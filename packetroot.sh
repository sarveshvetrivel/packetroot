#!/usr/bin/env bash

# =============================================================================
# PacketRoot - Advanced PCAP/PCAPNG Forensic & CTF Analysis Toolkit
# Version: 2.0.0 Enhanced Edition
# Author: Sarvesh Vetrivel
# GitHub: https://github.com/sarveshvetrivel/packetroot
# License: Apache 2.0
# Description: Comprehensive network traffic analysis and forensic investigation
#              tool for security researchers and CTF players.
# =============================================================================

# Exit Codes:
#   0 - Success
#   1 - General error
#   2 - Invalid arguments
#   3 - Missing dependencies
#   4 - File not found or inaccessible
#   5 - Permission denied
#   6 - Invalid PCAP/PCAPNG file
#   7 - Analysis interrupted by user
#   8 - Out of disk space
#   9 - Out of memory
#  10 - Security issues found (non-fatal)

# Enable strict mode
set -euo pipefail
IFS=$'\n\t'

# Constants
readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly OUTPUT_BASE_DIR="${SCRIPT_DIR}/output"
readonly VERSION="2.0.0"
readonly RELEASE_DATE="2025-09-01"
readonly MINIMUM_BASH_VERSION=4.2
readonly MINIMUM_TSHARK_VERSION=3.0.0
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly MAX_FILE_SIZE=$((2 * 1024 * 1024 * 1024))  # 2GB
readonly MAX_PACKETS=1000000  # For large files

# Security settings
readonly ALLOWED_PROTOCOLS=("http" "https" "dns" "tcp" "udp" "smtp" "ftp" "smb" "smb2" "ntp" "dhcp" "tls" "ssh" "icmp" "arp" "rtp" "sip")
readonly ALLOWED_ANALYSIS=("metadata" "traffic" "protocols" "streams" "carve" "media" "ids" "ctf" "timeline" "icmp" "voip" "entropy")

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'  # No Color

# Global variables (ENHANCED)
declare -a MISSING_TOOLS=()
declare -a CTF_KEYWORDS=()
declare -a PROTOCOLS=()
declare -a MISSING_OPTIONAL_TOOLS=()
declare -g OUTPUT_DIR=""
declare -g INPUT_FILE=""
declare -g TIMELINE_MODE="false"
declare -g EXPORT_FORMAT=""
declare -g ENABLE_PARALLEL="false"
declare -g CONFIG_FILE="$SCRIPT_DIR/packetroot.conf"
declare -g RUN_ICMP="false"
declare -g RUN_VOIP="false"
declare -g RUN_ENTROPY="false"
# Additional modes & user-configurable globals
declare -g MODE="normal"          # quick | deep | normal
declare -g CTF_PATTERN=""         # single pattern via -c/--ctf (legacy)
declare -g CUSTOM_OUTPUT_DIR=""   # override output dir via -o/--output
declare -g INTERACTIVE_MODE="false" # -i / --interactive


# Cleanup function to be called on script exit
declare -a CLEANUP_FILES=()
cleanup() {
    local exit_code=$?
    
    # Cleanup temporary files
    if [[ ${#CLEANUP_FILES[@]} -gt 0 ]]; then
        rm -f "${CLEANUP_FILES[@]}" 2>/dev/null || true
    fi
    
    # Restore original directory
    popd &>/dev/null || true
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Function to print colored banner with ASCII art
print_banner() {
    [[ $# -eq 0 ]] && return 1
    
    local message="$1"
    local color="${2:-$CYAN}"
    local width=80
    local padding=$(( (width - ${#message} - 2) / 2 ))
    
    # Ensure padding is not negative
    [[ $padding -lt 0 ]] && padding=0
    
    # ASCII Art Banner
    local banner="${color}"
    banner+="╔══════════════════════════════════════════════════════════════════════════════╗\n"
    banner+="║  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗  ██████╗  ██████╗ ████████╗  ║\n"
    banner+="║  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝  ║\n"
    banner+="║  ██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██████╔╝██║   ██║██║   ██║   ██║     ║\n"
    banner+="║  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██╔══██╗██║   ██║██║   ██║   ██║     ║\n"
    banner+="║  ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║  ██║╚██████╔╝╚██████╔╝   ██║     ║\n"
    banner+="║  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝     ║\n"
    banner+="╠══════════════════════════════════════════════════════════════════════════════╣\n"
    banner+="║  ${WHITE}PCAP/PCAPNG Forensic & CTF Analysis Toolkit v${VERSION}${color}                 ║\n"
    banner+="╠══════════════════════════════════════════════════════════════════════════════╣\n"
    banner+="║  ${WHITE}${message}${color}"
    banner+="$(printf "%$((width - ${#message} - 4))s")"
    banner+="  ║\n"
    banner+="╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n$banner\n"
}

# Function to print status messages
print_status() {
    [[ $# -lt 2 ]] && { echo -e "${RED}[ERROR]${NC} print_status: Missing arguments" >&2; return 1; }
    
    local status="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$status" in
        "INFO")    echo -e "${BLUE}[${timestamp}] [INFO]${NC} $message" ;;
        "WARN")    echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $message" ;;
        "ERROR")   echo -e "${RED}[${timestamp}] [ERROR]${NC} $message" >&2 ;;
        "SUCCESS") echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} $message" ;;
        "PROGRESS") echo -e "${PURPLE}[${timestamp}] [+]${NC} $message" ;;
        "DEBUG")   [[ "${DEBUG:-false}" == "true" ]] && echo -e "${WHITE}[${timestamp}] [DEBUG]${NC} $message" >&2 ;;
        *)          echo -e "${WHITE}[${timestamp}] [$status]${NC} $message" ;;
    esac
    
    return 0
}

# Function to check if a tool is available
check_tool() {
    local tool="$1"
    if command -v "$tool" &> /dev/null; then
        return 0
    else
        MISSING_TOOLS+=("$tool")
        return 1
    fi
}

# Function to create output directory structure
create_output_structure() {
    local input_file="$1"
    local basename
    basename=$(basename "$input_file" | sed 's/\.[^.]*$//')
    
    if [[ -n "${CUSTOM_OUTPUT_DIR:-}" ]]; then
        # Use absolute path if provided
        OUTPUT_DIR="$(realpath -m "${CUSTOM_OUTPUT_DIR}/${basename}_${TIMESTAMP}")"
    else
        OUTPUT_DIR="${OUTPUT_BASE_DIR}/${basename}_${TIMESTAMP}"
    fi
    
        # Create a minimal set of directories; others will be created when modules run
    if ! mkdir -p "${OUTPUT_DIR}/reports" "${OUTPUT_DIR}/timeline"; then
        print_status "ERROR" "Failed to create minimal output directories"
        return 1
    fi

    
    print_status "SUCCESS" "Output directory created: $OUTPUT_DIR"
}

# Function to safely get file information with error handling
safe_stat() {
    local file="$1"
    local format="$2"
    local default="$3"
    
    # Check if file exists and is readable
    if [[ ! -r "$file" ]]; then
        echo "$default"
        return 1
    fi
    
    # Get file information
    local result
    if result=$(stat -c "$format" -- "$file" 2>/dev/null); then
        echo "$result"
        return 0
    else
        echo "$default"
        return 1
    fi
}

# Function to calculate file hash with error handling
calculate_hash() {
    local file="$1"
    local algo="$2"
    local default="$3"
    
    # Check if file exists and is readable
    if [[ ! -r "$file" ]]; then
        echo "$default"
        return 1
    fi
    
    # Calculate hash based on algorithm
    case "$algo" in
        md5)
            if command -v md5sum &>/dev/null; then
                local hash_result
                hash_result=$(md5sum -- "$file" 2>/dev/null)
            else
                echo "$default (md5sum not available)"
                return 1
            fi
            ;;
        sha1)
            if command -v sha1sum &>/dev/null; then
                local hash_result
                hash_result=$(sha1sum -- "$file" 2>/dev/null)
            else
                echo "$default (sha1sum not available)"
                return 1
            fi
            ;;
        sha256)
            if command -v sha256sum &>/dev/null; then
                local hash_result
                hash_result=$(sha256sum -- "$file" 2>/dev/null)
            else
                echo "$default (sha256sum not available)"
                return 1
            fi
            ;;
        sha512)
            if command -v sha512sum &>/dev/null; then
                local hash_result
                hash_result=$(sha512sum -- "$file" 2>/dev/null)
            else
                echo "$default (sha512sum not available)"
                return 1
            fi
            ;;
        *)
            echo "$default (unsupported algorithm: $algo)"
            return 1
            ;;
    esac
    
    # Extract just the hash part
    if [[ $? -eq 0 ]] && [[ -n "$hash_result" ]]; then
        echo "${hash_result%% *}"
        return 0
    else
        echo "$default"
        return 1
    fi
}

# Function to safely execute commands with proper error handling and security
run_command() {
    # Input validation
    if [[ $# -ne 3 ]]; then
        print_status "ERROR" "run_command: Invalid number of arguments (expected 3, got $#)"
        return 2
    fi
    
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    local start_time
    start_time=$(date +%s)
    
    # Validate command
    if [[ -z "$cmd" ]]; then
        print_status "ERROR" "Command cannot be empty"
        return 2
    fi
    
    # Validate output file path
    if [[ -z "$output_file" ]]; then
        print_status "ERROR" "Output file path cannot be empty"
        return 2
    fi
    
    # Resolve absolute path and validate
    output_file=$(realpath -m "$output_file" 2>/dev/null || echo "$output_file")
    if [[ "$output_file" == "/"* ]]; then
        # Ensure the output directory exists and is writable
        local output_dir
        output_dir=$(dirname "$output_file")
        
        if ! mkdir -p "$output_dir" 2>/dev/null; then
            print_status "ERROR" "Failed to create output directory: $output_dir"
            return 2
        fi
        
        if [[ ! -w "$output_dir" ]]; then
            print_status "ERROR" "No write permission for directory: $output_dir"
            return 2
        fi
    else
        print_status "ERROR" "Output path must be absolute: $output_file"
        return 2
    fi
    
    # Generate a secure temporary file
    local temp_output
    temp_output=$(mktemp "${output_file}.XXXXXX" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        print_status "ERROR" "Failed to create temporary file for: $output_file"
        return 2
    fi
    
    # Add to cleanup list
    CLEANUP_FILES+=("$temp_output")
    
    # Log the command being executed (sanitized)
    print_status "DEBUG" "Executing: $cmd"
    print_status "PROGRESS" "$description"
    
    # Set command timeout (5 minutes by default, longer for specific commands)
    local max_runtime=300  # 5 minutes in seconds
    local cmd_name
    cmd_name=$(echo "$cmd" | awk '{print $1}')
    
    case "$cmd_name" in
        tshark|zeek|suricata|binwalk|foremost|bulk_extractor)
            max_runtime=900  # 15 minutes for heavy analysis
            ;;
    esac
    
    # Execute the command with timeout
    if command -v timeout &>/dev/null; then
        if timeout $max_runtime bash -c "$cmd" > "$temp_output" 2>&1; then
            local exit_status=0
        else
            local exit_status=$?
        fi
    else
        # Fallback for systems without timeout command
        if eval "$cmd" > "$temp_output" 2>&1; then
            local exit_status=0
        else
            local exit_status=$?
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Handle command output
    if [[ $exit_status -eq 0 ]]; then
        # Command succeeded, move temp file to final location
        if mv "$temp_output" "$output_file" 2>/dev/null; then
            print_status "SUCCESS" "Completed in ${duration}s: $description"
        else
            print_status "ERROR" "Failed to save command output"
            return 2
        fi
    else
        # Command failed, save error output
        local error_msg="Command failed with status $exit_status"
        if [[ -f "$temp_output" ]]; then
            # Add first line of error output to the message
            local first_line
            first_line=$(head -n 1 "$temp_output" 2>/dev/null || echo "No output")
            error_msg+=" - ${first_line:0:200}"  # Truncate long error messages
            
            # Save the full error output
            mv "$temp_output" "${output_file}.error" 2>/dev/null || true
        fi
        
        print_status "WARN" "$error_msg (details in ${output_file}.error)"
    fi
    
    return $exit_status
}

# Function to safely run tshark with common options and error handling
run_tshark_analysis() {
    # Input validation
    if [[ $# -ne 4 ]]; then
        print_status "ERROR" "run_tshark_analysis: Invalid number of arguments (expected 4, got $#)"
        return 2
    fi
    
    local input_file="$1"
    local output_file="$2"
    local stats_type="$3"
    local description="$4"
    local start_time
    start_time=$(date +%s)
    
    # Validate input file
    if [[ ! -f "$input_file" ]] || [[ ! -r "$input_file" ]]; then
        print_status "ERROR" "Cannot read input file: $input_file"
        return 1
    fi
    
    # Validate output directory
    local output_dir
    output_dir=$(dirname "$output_file" 2>/dev/null)
    if [[ -z "$output_dir" ]] || [[ ! -d "$output_dir" ]]; then
        print_status "ERROR" "Invalid output directory: $output_dir"
        return 1
    fi
    
    if [[ ! -w "$output_dir" ]]; then
        print_status "ERROR" "No write permission for directory: $output_dir"
        return 1
    fi
    
    # Validate stats type
    if [[ -z "$stats_type" ]]; then
        print_status "ERROR" "Statistics type cannot be empty"
        return 1
    fi
    
    # Check file size to determine processing limits
    local file_size
    file_size=$(safe_stat "$input_file" "%s" "0")
    
    # Set maximum packets based on file size
    local max_packets=0  # 0 means unlimited
    
    if [[ $file_size -gt 1073741824 ]]; then  # If file > 1GB
        max_packets=1000000  # Limit to 1 million packets
        print_status "WARN" "Large file detected (${file_size} bytes). Limiting analysis to $max_packets packets for: $description"
    elif [[ $file_size -eq 0 ]]; then
        print_status "ERROR" "Input file is empty: $input_file"
        return 1
    fi
    
    # Build the tshark command with proper argument handling
    local cmd="tshark -r \"$input_file\" -q"
    
    # Add packet limit if needed
    if [[ $max_packets -gt 0 ]]; then
        cmd+=" -c $max_packets"
    fi
    
    # Add statistics option with validation
    if [[ "$stats_type" == *\'* ]] || [[ "$stats_type" == *\"* ]] || 
       [[ "$stats_type" == *\$* ]] || [[ "$stats_type" == *\`* ]] || 
       [[ "$stats_type" == *\&* ]] || [[ "$stats_type" == *\;* ]] || 
       [[ "$stats_type" == *\|* ]] || [[ "$stats_type" == *\<* ]] || 
       [[ "$stats_type" == *\>* ]] || [[ "$stats_type" == *\(* ]] || 
       [[ "$stats_type" == *\)* ]] || [[ "$stats_type" == *\{* ]] || 
       [[ "$stats_type" == *\}* ]]; then
        print_status "ERROR" "Invalid characters in statistics type: $stats_type"
        return 1
    fi
    
    cmd+=" -z \"$stats_type\""
    
    # Run the command with proper error handling
    if ! run_command "$cmd" "$output_file" "$description"; then
        print_status "ERROR" "Failed to complete tshark analysis for: $description"
        
        # If the output file exists but is empty, remove it
        if [[ -f "$output_file" ]] && [[ ! -s "$output_file" ]]; then
            rm -f "$output_file" 2>/dev/null || true
        fi
        
        return 1
    fi
    
    # Verify the output file was created and has content
    if [[ ! -s "$output_file" ]]; then
        print_status "WARN" "Analysis completed but output file is empty: $output_file"
        return 1
    fi
    
    # Log successful completion
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    print_status "DEBUG" "Completed $description in ${duration} seconds"
    print_status "INFO" "Results saved to: $output_file"
    
    return 0
}

# --- NEW FUNCTION: Analyze ICMP Traffic ---
analyze_icmp() {
    local input_file="$1"
    local icmp_dir="$OUTPUT_DIR/icmp_analysis"
    mkdir -p "$icmp_dir"

    if ! check_tool "tshark"; then
        print_status "WARN" "tshark not available, skipping ICMP analysis"
        return 1
    fi

    print_status "INFO" "Starting ICMP analysis..."
    run_tshark_analysis "$input_file" "$icmp_dir/icmp_stats.txt" "icmp,tree" "ICMP statistics"

    tshark -r "$input_file" -Y "icmp" -T fields \
        -e frame.number -e frame.time -e ip.src -e ip.dst -e icmp.type -e icmp.code \
        -e data.data > "$icmp_dir/icmp_detailed.txt" 2>/dev/null || true

    # Ping request/reply analysis
    tshark -r "$input_file" -Y "icmp.type==8" -T fields -e ip.src -e ip.dst \
        -e icmp.seq -e icmp.id > "$icmp_dir/ping_requests.txt" 2>/dev/null || true
    
    tshark -r "$input_file" -Y "icmp.type==0" -T fields -e ip.src -e ip.dst \
        -e icmp.seq -e icmp.id > "$icmp_dir/ping_replies.txt" 2>/dev/null || true

    print_status "SUCCESS" "Completed ICMP analysis"
}

# --- NEW FUNCTION: Analyze VoIP (RTP, SIP) ---
analyze_voip() {
    local input_file="$1"
    local voip_dir="$OUTPUT_DIR/voip_analysis"
    mkdir -p "$voip_dir"

    if ! check_tool "tshark"; then
        print_status "WARN" "tshark not available, skipping VoIP analysis"
        return 1
    fi

    print_status "INFO" "Starting VoIP analysis..."
    
    # RTP streams
    tshark -r "$input_file" -Y "rtp" -T fields -e rtp.ssrc -e rtp.seq \
        -e rtp.timestamp -e rtp.payload > "$voip_dir/rtp_streams.txt" 2>/dev/null || true

    # SIP messages
    tshark -r "$input_file" -Y "sip" -T fields -e sip.Method -e sip.Call-ID \
        -e sip.From -e sip.To > "$voip_dir/sip_messages.txt" 2>/dev/null || true

    # RTCP analysis
    tshark -r "$input_file" -Y "rtcp" -T fields -e rtcp.pt -e rtcp.ssrc \
        > "$voip_dir/rtcp_analysis.txt" 2>/dev/null || true

    print_status "SUCCESS" "Completed VoIP analysis"
}

# --- NEW FUNCTION: Export Results ---
export_results() {
    local fmt="$1"
    
    if [[ -z "$fmt" ]]; then
        return 0
    fi
    
    mkdir -p "$OUTPUT_DIR/exports"

    if ! check_tool "tshark"; then
        print_status "WARN" "tshark not available, skipping export"
        return 1
    fi

    print_status "INFO" "Exporting results in $fmt format..."

    case "$fmt" in
        json)
            tshark -r "$INPUT_FILE" -T json > "$OUTPUT_DIR/exports/packets.json" 2>/dev/null || true
            print_status "SUCCESS" "Exported results to JSON"
            ;;
        csv)
            tshark -r "$INPUT_FILE" -T fields -E separator=, \
                -e frame.number -e frame.time -e ip.src -e ip.dst \
                -e _ws.col.Protocol > "$OUTPUT_DIR/exports/packets.csv" 2>/dev/null || true
            print_status "SUCCESS" "Exported results to CSV"
            ;;
        xml)
            tshark -r "$INPUT_FILE" -T pdml > "$OUTPUT_DIR/exports/packets.xml" 2>/dev/null || true
            print_status "SUCCESS" "Exported results to XML"
            ;;
        *)
            print_status "WARN" "Unsupported export format: $fmt"
            ;;
    esac
}

# --- NEW FUNCTION: Load Plugins ---
load_plugins() {
    local plugin_dir="$SCRIPT_DIR/plugins"
    if [[ -d "$plugin_dir" ]]; then
        print_status "INFO" "Loading plugins from $plugin_dir"
        for plugin in "$plugin_dir"/*.sh; do
            if [[ -f "$plugin" ]]; then
                source "$plugin" && print_status "INFO" "Loaded plugin: $(basename "$plugin")"
            fi
        done
    fi
}

# --- NEW FUNCTION: Load Configuration ---
load_config() {
    local config_file="${CONFIG_FILE:-$SCRIPT_DIR/packetroot.conf}"
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        print_status "INFO" "Loaded config file: $config_file"
    fi
}

# --- NEW FUNCTION: Analyze Entropy ---
analyze_entropy() {
    local search_dir="${1:-$OUTPUT_DIR}"

    print_status "INFO" "Starting entropy analysis in $search_dir..."

    local entropy_dir="$OUTPUT_DIR/entropy_analysis"
    mkdir -p "$entropy_dir"

    # Find potentially high-entropy files (compressed/encrypted data)
    find "$search_dir" -type f -size +1M -exec file {} \; | \
        grep -E "(data|compressed|encrypted)" > "$entropy_dir/high_entropy_candidates.txt" 2>/dev/null || true

    # Look for base64 patterns in traffic
    if check_tool "tshark" && [[ -f "$INPUT_FILE" ]]; then
        tshark -r "$INPUT_FILE" -Y "http and data.text matches \"[A-Za-z0-9+/=]{20,}\"" \
            -T fields -e frame.number -e data.text > "$entropy_dir/base64_patterns.txt" 2>/dev/null || true
    fi

    print_status "SUCCESS" "Completed entropy analysis"
}

# --- NEW FUNCTION: Enhanced Protocol Analysis ---
analyze_additional_protocols() {
    local input_file="$1"
    local protocols_dir="$OUTPUT_DIR/protocols"
    
    print_status "INFO" "Starting additional protocol analysis..."

    # ARP analysis
    tshark -r "$input_file" -Y "arp" -T fields -e arp.opcode -e arp.src.hw_mac \
        -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 > "$protocols_dir/arp_analysis.txt" 2>/dev/null || true

    # DHCP analysis
    tshark -r "$input_file" -Y "dhcp" -T fields -e dhcp.option.dhcp_message_type \
        -e dhcp.option.hostname -e dhcp.option.domain_name > "$protocols_dir/dhcp_analysis.txt" 2>/dev/null || true

    # NTP analysis
    tshark -r "$input_file" -Y "ntp" -T fields -e ntp.stratum -e ntp.reference_id \
        -e ntp.rootdelay > "$protocols_dir/ntp_analysis.txt" 2>/dev/null || true

    print_status "SUCCESS" "Completed additional protocol analysis"
}

# --- NEW FUNCTION: Run Parallel Analysis ---
run_parallel() {
    if [[ "$ENABLE_PARALLEL" != "true" ]]; then
        return 0
    fi

    print_status "INFO" "Starting parallel analysis modules..."
    
    # Run additional analyses in parallel
    analyze_icmp "$INPUT_FILE" &
    analyze_voip "$INPUT_FILE" &
    analyze_additional_protocols "$INPUT_FILE" &
    
    # Wait for all background processes to complete
    wait
    
    print_status "INFO" "Parallel analysis modules completed"
}

interactive_menu() {
    local file="${1:-$INPUT_FILE}"

    # Ensure input file resolved
    if [[ -z "$file" ]]; then
        print_status "ERROR" "No input file specified for interactive menu"
        return 1
    fi

    # Ensure output structure exists before menu actions
    if [[ -z "$OUTPUT_DIR" || ! -d "$OUTPUT_DIR" ]]; then
        create_output_structure "$file" || { print_status "ERROR" "Failed to create output dir"; return 1; }
    fi

    # Menu loop
    while true; do
        echo
        print_banner "Interactive Menu" "$CYAN"
        echo "1) Metadata analysis"
        echo "2) Protocol statistics (traffic)"
        echo "3) Protocol extraction"
        echo "4) Security/IDS findings (Zeek/Suricata)"
        echo "5) File carving"
        echo "6) Stream reassembly / extraction"
        echo "7) Media & steganography analysis"
        echo "8) CTF / Keyword search"
        echo "9) Timeline generation"
        echo "10) Run all modules (quick/deep obeyed)"
        echo "11) View summary"
        echo "0) Exit interactive mode"
        echo

        read -p "Select an option [0-11]: " choice
        case "$choice" in
            1)
                extract_metadata "$file"
                ;;
            2)
                analyze_traffic "$file"
                ;;
            3)
                extract_protocols "$file"
                ;;
            4)
                run_ids_analysis "$file"
                ;;
            5)
                carve_files "$file"
                ;;
            6)
                reassemble_streams "$file"
                ;;
            7)
                analyze_media_steg "$file"
                ;;
            8)
                # prompt for ad-hoc keyword if none passed
                if [[ ${#CTF_KEYWORDS[@]} -gt 0 ]]; then
                    search_ctf_keywords "$file"
                else
                    read -p "Enter keyword/pattern to search for: " user_kw
                    if [[ -n "$user_kw" ]]; then
                        CTF_KEYWORDS+=("$user_kw")
                        search_ctf_keywords "$file"
                    else
                        print_status "WARN" "No keyword supplied"
                    fi
                fi
                ;;
            9)
                generate_timeline "$file"
                ;;
            10)
                # Run full analysis respecting quick/deep mode
                if [[ "$MODE" == "quick" || "$quick_mode" == "true" ]]; then
                    print_status "INFO" "Running QUICK analysis..."
                    extract_metadata "$file"
                    analyze_traffic "$file"
                    reassemble_streams "$file"
                    search_ctf_keywords "$file"
                else
                    print_status "INFO" "Running FULL analysis..."
                    extract_metadata "$file"
                    analyze_traffic "$file"
                    extract_protocols "$file"
                    reassemble_streams "$file"
                    carve_files "$file"
                    analyze_media_steg "$file"
                    run_ids_analysis "$file"
                    search_ctf_keywords "$file"
                    analyze_entropy "$file"
                    generate_timeline "$file"
                fi
                ;;
            11)
                generate_summary
                less "${OUTPUT_DIR}/summary.txt"
                ;;
            0)
                print_status "INFO" "Exiting interactive mode"
                break
                ;;
            *)
                print_status "WARN" "Invalid selection: $choice"
                ;;
        esac
    done
}

# Function to extract file metadata with comprehensive error handling
extract_metadata() {
    # Input validation
    if [[ $# -ne 1 ]] || [[ -z "$1" ]]; then
        print_status "ERROR" "extract_metadata: Missing or invalid input file"
        return 1
    fi
    
    local input_file="$1"
    local start_time
    start_time=$(date +%s)
    
    # Validate input file path
    if [[ ! -e "$input_file" ]]; then
        print_status "ERROR" "Input file does not exist: $input_file"
        return 1
    fi
    
    if [[ ! -f "$input_file" ]]; then
        print_status "ERROR" "Not a regular file: $input_file"
        return 1
    fi
    
    if [[ ! -r "$input_file" ]]; then
        print_status "ERROR" "Cannot read input file (permission denied): $input_file"
        return 1
    fi
    
    # Check for symbolic links and resolve them
    if [[ -L "$input_file" ]]; then
        print_status "WARN" "Input is a symbolic link, following to target"
        input_file=$(readlink -f "$input_file" 2>/dev/null || echo "$input_file")
        
        if [[ ! -f "$input_file" ]]; then
            print_status "ERROR" "Symbolic link target is not a regular file: $input_file"
            return 1
        fi
    fi
    
    print_status "INFO" "Starting file metadata analysis..."
    
    # Create secure temporary file for output
    local temp_file
    temp_file=$(mktemp "${OUTPUT_DIR}/.metadata_XXXXXX" 2>/dev/null)
    
    if [[ $? -ne 0 ]] || [[ ! -f "$temp_file" ]]; then
        print_status "ERROR" "Failed to create temporary file for metadata extraction"
        return 1
    fi
    
    # Add to cleanup list
    CLEANUP_FILES+=("$temp_file")
    
    # Create reports directory
    local reports_dir="$OUTPUT_DIR/reports"
    if ! mkdir -p "$reports_dir" 2>/dev/null; then
        print_status "ERROR" "Failed to create reports directory: $reports_dir"
        return 1
    fi
    
    # Set secure permissions on reports directory
    chmod 700 "$reports_dir" 2>/dev/null || true
    
    # Check file size and warn if too large
    local file_size
    file_size=$(safe_stat "$input_file" "%s" "0")
    
    if [[ $file_size -gt 1073741824 ]]; then  # 1GB
        print_status "WARN" "Large file detected (over 1GB). Analysis may take a while..."
    elif [[ $file_size -eq 0 ]]; then
        print_status "WARN" "Empty file detected"
    fi
    
    # Get file information with error handling
    declare -A file_info=(
        ["File"]="$input_file"
        ["Size"]="$(numfmt --to=iec $file_size 2>/dev/null || echo "$file_size bytes")"
        ["Type"]="$(file -b -- "$input_file" 2>/dev/null || echo "unknown")"
        ["Inode"]="$(safe_stat "$input_file" "%i" "unknown")"
        ["Links"]="$(safe_stat "$input_file" "%h" "unknown")"
        ["Permissions"]="$(stat -c "%A %a %U:%G" -- "$input_file" 2>/dev/null || echo "unknown")"
        ["Created"]="$(safe_stat "$input_file" "%w" "unknown")"
        ["Modified"]="$(safe_stat "$input_file" "%y" "unknown")"
        ["Accessed"]="$(safe_stat "$input_file" "%x" "unknown")"
    )
    
    # Write basic file information
    {
        echo "=== FILE METADATA ==="
        for key in "${!file_info[@]}"; do
            printf "%-12s: %s\n" "$key" "${file_info[$key]}"
        done
        
        echo -e "\n=== FILE HASHES ==="
        # Always calculate basic hashes
        for algo in "md5" "sha1" "sha256"; do
            printf "%-8s: %s\n" "${algo^^}" "$(calculate_hash "$input_file" "$algo" "failed")"
        done
        
        # Only calculate additional hashes for smaller files
        if [[ $file_size -lt 10485760 ]]; then  # 10MB
            echo -e "\n=== ADDITIONAL HASHES (for files < 10MB) ==="
            printf "%-8s: %s\n" "SHA512" "$(calculate_hash "$input_file" "sha512" "not calculated")"
        fi
        
        # Add file signature analysis
        echo -e "\n=== FILE SIGNATURE ==="
        if [[ $file_size -gt 0 ]]; then
            # Read first few bytes for signature analysis
            local sig
            sig=$(dd if="$input_file" bs=16 count=1 2>/dev/null | xxd -p 2>/dev/null || echo "failed to read")
            echo "First 16 bytes (hex): ${sig:0:32}..."
        else
            echo "File is empty, no signature to analyze"
        fi
        
    } > "$temp_file"
    
    # Run capinfos if available (with timeout)
    if check_tool "capinfos"; then
        print_status "PROGRESS" "Running capinfos..."
        
        {
            echo -e "\n=== PCAP ANALYSIS (capinfos) ==="
            
            # Use timeout to prevent hanging on corrupt files
            if command -v timeout &>/dev/null; then
                timeout 30 capinfos -TmQ "$input_file" 2>/dev/null || \
                    echo "[WARNING] capinfos timed out or encountered an error"
            else
                capinfos -TmQ "$input_file" 2>/dev/null || \
                    echo "[WARNING] capinfos encountered an error"
            fi
        } >> "$temp_file"
    fi
    
    # Final output file path with timestamp
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="${reports_dir}/file_metadata_${timestamp}.txt"
    
    # Atomic move to final destination
    if mv "$temp_file" "$output_file" 2>/dev/null; then
        # Set secure permissions
        chmod 600 "$output_file" 2>/dev/null || true
        
        # Remove from cleanup list since we've moved it
        CLEANUP_FILES=("${CLEANUP_FILES[@]/$temp_file}")
        
        # Calculate and log processing time
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - ${start_time:-end_time}))
        
        print_status "SUCCESS" "Metadata extraction completed in ${duration} seconds"
        print_status "INFO" "Results saved to: $output_file"
        
        return 0
    else
        print_status "ERROR" "Failed to save metadata to: $output_file"
        return 1
    fi
}

# Function to analyze traffic summaries with comprehensive error handling
analyze_traffic() {
    # Input validation
    if [[ $# -ne 1 ]] || [[ -z "$1" ]]; then
        print_status "ERROR" "analyze_traffic: Missing or invalid input file"
        return 1
    fi
    
    local input_file="$1"
    local start_time
    start_time=$(date +%s)
    
    # Validate input file
    if [[ ! -f "$input_file" ]] || [[ ! -r "$input_file" ]]; then
        print_status "ERROR" "Cannot read input file: $input_file"
        return 1
    fi
    
    # Check file size
    local file_size
    file_size=$(safe_stat "$input_file" "%s" "0")
    if [[ $file_size -eq 0 ]]; then
        print_status "ERROR" "Input file is empty: $input_file"
        return 1
    fi
    
    print_status "INFO" "Starting traffic analysis..."
    
    # Create reports directory
    local reports_dir="$OUTPUT_DIR/reports"
    if ! mkdir -p "$reports_dir" 2>/dev/null; then
        print_status "ERROR" "Failed to create reports directory: $reports_dir"
        return 1
    fi
    
    # Check file type to ensure it's a capture file
    local file_type
    file_type=$(file -b -- "$input_file" 2>/dev/null || echo "unknown")
    if ! [[ "$file_type" =~ (pcap|pcapng|tcpdump|Wireshark|capture) ]]; then
        print_status "WARN" "File does not appear to be a network capture (detected as: $file_type)"
    fi
    
    # Run tshark analyses with proper error handling
    local success_count=0
    local total_analyses=0
    
    # ENHANCED: Define analyses to run including new protocol support
    # ENHANCED: Define analyses to run including new protocol support
local -a analyses=(
    "I/O statistics" "io,stat,0" "$reports_dir/io_stats.txt"
    "Protocol hierarchy" "io,phs" "$reports_dir/protocol_hierarchy.txt"
    "IP endpoints" "endpoints,ip" "$reports_dir/ip_endpoints.txt"
    "TCP endpoints" "endpoints,tcp" "$reports_dir/tcp_endpoints.txt"
    "UDP endpoints" "endpoints,udp" "$reports_dir/udp_endpoints.txt"
    "IP conversations" "conv,ip" "$reports_dir/ip_conversations.txt"
    "TCP conversations" "conv,tcp" "$reports_dir/tcp_conversations.txt"
    "UDP conversations" "conv,udp" "$reports_dir/udp_conversations.txt"
    "HTTP statistics" "http,tree" "$reports_dir/http_stats.txt"
    "DNS statistics" "dns,tree" "$reports_dir/dns_stats.txt"
    "ICMP statistics" "io,stat,0,icmp" "$reports_dir/icmp_stats.txt"
    "ARP statistics" "io,stat,0,arp" "$reports_dir/arp_stats.txt"
)

    
    # Run each analysis
    for ((i=0; i<${#analyses[@]}; i+=3)); do
        local description="${analyses[i]}"
        local stats_type="${analyses[i+1]}"
        local output_file="${analyses[i+2]}"
        
        # Skip if output file already exists from a previous run
        if [[ -f "$output_file" ]]; then
            print_status "INFO" "Skipping (already exists): $description"
            continue
        fi
        
        print_status "PROGRESS" "Running: $description"
        ((total_analyses++))
        
        if run_tshark_analysis "$input_file" "$output_file" "$stats_type" "$description"; then
            ((success_count++))
            
            # Check if output file was actually created and has content
            if [[ ! -s "$output_file" ]]; then
                print_status "WARN" "Analysis completed but output file is empty or missing: $output_file"
                # Don't count as success if there's no output
                ((success_count--))
            fi
        fi
    done
    
    # Final status
    if [[ $success_count -eq 0 ]]; then
        print_status "ERROR" "Traffic analysis failed - no valid results generated"
        return 1
    elif [[ $success_count -lt $total_analyses ]]; then
        print_status "WARN" "Traffic analysis completed with $((total_analyses - success_count)) failures"
    else
        print_status "SUCCESS" "Traffic analysis completed successfully"
    fi
    
    return 0
}

# Function to extract protocols with comprehensive error handling and security
extract_protocols() {
    # Input validation
    if [[ $# -ne 1 ]] || [[ -z "$1" ]]; then
        print_status "ERROR" "extract_protocols: Missing or invalid input file"
        return 1
    fi
    
    local input_file="$1"
    local start_time
    start_time=$(date +%s)
    
    # Validate input file
    if [[ ! -f "$input_file" ]] || [[ ! -r "$input_file" ]]; then
        print_status "ERROR" "Cannot read input file: $input_file"
        return 1
    fi
    
    # Check file size
    local file_size
    file_size=$(safe_stat "$input_file" "%s" "0")
    if [[ $file_size -eq 0 ]]; then
        print_status "ERROR" "Input file is empty: $input_file"
        return 1
    fi
    
    print_status "INFO" "Starting protocol extraction from: $input_file"
    
    # Create output directories with secure permissions
    local protocols_dir="$OUTPUT_DIR/protocols"
    if ! mkdir -p "$protocols_dir" 2>/dev/null; then
        print_status "ERROR" "Failed to create protocols directory: $protocols_dir"
        return 1
    fi
    chmod 700 "$protocols_dir" 2>/dev/null || true
    
    # Check if tshark is available
    if ! check_tool "tshark"; then
        print_status "ERROR" "tshark not found in PATH. Protocol extraction requires tshark."
        return 1
    fi
    
    local success_count=0
    local total_analyses=0
    
    # Function to safely run protocol extraction (IMPROVED)
    run_protocol_analysis() {
        local filter="$1"
        local output_file="$2"
        local description="$3"
        shift 3
        local fields=("$@")
        
        # Skip if output file already exists from a previous run
        if [[ -f "$output_file" ]]; then
            print_status "INFO" "Skipping (already exists): $description"
            ((success_count++))
            return 0
        fi
        
        # Create parent directory if it doesn't exist
        local output_dir
        output_dir=$(dirname "$output_file")
        if ! mkdir -p "$output_dir" 2>/dev/null; then
            print_status "ERROR" "Failed to create output directory: $output_dir"
            return 1
        fi
        
        # Build the tshark command
        local cmd="tshark -r \"$input_file\" -Y \"$filter\""
        
        # Add fields if provided
        if [[ ${#fields[@]} -gt 0 ]]; then
            cmd+=" -T fields"
            for field in "${fields[@]}"; do
                cmd+=" -e \"$field\""
            done
        else
            cmd+=" -T pdml"  # Default to PDML if no fields specified
        fi
        
        # Run the command with proper error handling
        if run_command "$cmd" "$output_file" "$description"; then
            # Verify the output file was created and has content
            if [[ -s "$output_file" ]]; then
                ((success_count++))
                # Set secure permissions on the output file
                chmod 600 "$output_file" 2>/dev/null || true
                print_status "SUCCESS" "Found $description data"
                return 0
            else
                print_status "INFO" "No $description found in PCAP (normal - this protocol not present)"
                # Remove empty output file but don't count as failure
                rm -f "$output_file" 2>/dev/null || true
                ((success_count++))  # Count as success since no error occurred
                return 0
            fi
        else
            print_status "WARN" "Failed to run $description"
            # Clean up any partial output
            rm -f "$output_file" 2>/dev/null || true
            return 1
        fi
    }
    
    # HTTP Analysis
    print_status "PROGRESS" "Analyzing HTTP traffic..."
    ((total_analyses++))
    run_protocol_analysis "http" "$protocols_dir/http_requests.txt" "HTTP requests extraction" \
        "http.request.method" "http.request.uri" "http.host" "http.response.code"
    
    ((total_analyses++))
    run_protocol_analysis "http" "$protocols_dir/http_full.xml" "Full HTTP analysis (XML)"
    
    # DNS Analysis (FIXED - compatible fields)
    print_status "PROGRESS" "Analyzing DNS traffic..."
    ((total_analyses++))
    run_protocol_analysis "dns" "$protocols_dir/dns_queries.txt" "DNS queries extraction" \
        "dns.qry.name" "dns.a"
    
    # TLS/SSL Analysis
    print_status "PROGRESS" "Analyzing TLS traffic..."
    ((total_analyses++))
    run_protocol_analysis "tls.handshake.type == 1" "$protocols_dir/tls_sni.txt" "TLS Server Name Indication" \
        "tls.handshake.extensions_server_name" "ip.src" "tcp.srcport" "ip.dst" "tcp.dstport"
    
    # FTP Analysis
    print_status "PROGRESS" "Analyzing FTP traffic..."
    ((total_analyses++))
    run_protocol_analysis "ftp" "$protocols_dir/ftp_commands.txt" "FTP commands extraction" \
        "ftp.request.command" "ftp.request.arg" "ip.src" "tcp.srcport" "ip.dst" "tcp.dstport"
    
    # SMTP Analysis (FIXED - compatible fields)
    print_status "PROGRESS" "Analyzing SMTP traffic..."
    ((total_analyses++))
    run_protocol_analysis "smtp" "$protocols_dir/smtp_commands.txt" "SMTP commands extraction" \
        "smtp.req.command"
    
    # SMB Analysis
    print_status "PROGRESS" "Analyzing SMB traffic..."
    ((total_analyses++))
    run_protocol_analysis "smb || smb2" "$protocols_dir/smb_activity.txt" "SMB activity extraction" \
        "smb.cmd" "smb2.cmd" "smb.path" "smb2.filename" "smb2.create.action"
    
    # Generate a summary of the protocol extraction
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    local summary_file="$protocols_dir/extraction_summary.txt"
    {
        echo "=== Protocol Extraction Summary ==="
        echo "Date: $(date)"
        echo "Input file: $input_file"
        echo "Analysis duration: ${duration} seconds"
        echo "Analyses completed: $success_count of $total_analyses"
        echo ""
        
        if [[ $success_count -eq $total_analyses ]]; then
            echo "SUCCESS: All protocol analyses completed successfully"
        else
            echo "PARTIAL: $success_count of $total_analyses analyses completed"
        fi
        
        echo ""
        echo "=== Generated Files ==="
        find "$protocols_dir" -type f -exec ls -lh {} \; 2>/dev/null || true
    } > "$summary_file"
    
    # Set secure permissions on all generated files
    find "$protocols_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
    
    print_status "SUCCESS" "Protocol extraction completed successfully"
    return 0
}


# Function to reassemble streams
reassemble_streams() {
    local input_file="$1"
    
    print_status "INFO" "Starting stream reassembly..."
    
    local streams_dir="$OUTPUT_DIR/streams"
    if ! mkdir -p "$streams_dir"; then
        print_status "ERROR" "Failed to create streams directory"
        return 1
    fi
    
    # tcpflow
    if check_tool "tcpflow"; then
        local original_dir=$(pwd)
        if cd "$streams_dir" 2>/dev/null; then
            run_command "tcpflow -r \"$input_file\"" "$streams_dir/tcpflow.log" "TCP flow reassembly (tcpflow)"
            cd "$original_dir" || print_status "WARN" "Failed to return to original directory"
        else
            print_status "ERROR" "Failed to change to streams directory"
        fi
    fi
    
    # tshark follow streams
    if check_tool "tshark"; then
        # Get list of TCP streams
        local tcp_streams
        tcp_streams=$(tshark -r "$input_file" -T fields -e tcp.stream 2>/dev/null | sort -n | uniq | head -20)
        
        if [[ -n "$tcp_streams" ]]; then
            while IFS= read -r stream; do
                if [[ -n "$stream" ]] && [[ "$stream" =~ ^[0-9]+$ ]]; then
                    local stream_cmd="tshark -r \"$input_file\" -q -z follow,tcp,ascii,$stream"
                    run_command "$stream_cmd" "$streams_dir/tcp_stream_$stream.txt" "TCP stream $stream reassembly"
                fi
            done <<< "$tcp_streams"
        fi
        
        print_status "SUCCESS" "Stream reassembly completed"
    fi
}

# Function to carve files
carve_files() {
    local input_file="$1"
    
    print_status "INFO" "Starting file carving..."
    
    local carved_dir="$OUTPUT_DIR/carved"
    if ! mkdir -p "$carved_dir"; then
        print_status "ERROR" "Failed to create carved directory"
        return 1
    fi
    
    # foremost
    if check_tool "foremost"; then
        run_command "foremost -i \"$input_file\" -o \"$carved_dir/foremost\"" "$carved_dir/foremost.log" "File carving with foremost"
    fi
    
    # binwalk (if available)
    if check_tool "binwalk"; then
        run_command "binwalk -e \"$input_file\" --directory=\"$carved_dir/binwalk\"" "$carved_dir/binwalk.log" "File analysis with binwalk"
    fi
    
    # bulk_extractor (if available)
    if check_tool "bulk_extractor"; then
        run_command "bulk_extractor -o \"$carved_dir/bulk_extractor\" \"$input_file\"" "$carved_dir/bulk_extractor.log" "Bulk extraction"
    fi
    
    print_status "SUCCESS" "File carving completed"
}

# Function to analyze media and steganography
analyze_media_steg() {
    local input_file="$1"
    
    print_status "INFO" "Starting media & steganography analysis..."
    
    local objects_dir="$OUTPUT_DIR/objects"
    if ! mkdir -p "$objects_dir"; then
        print_status "ERROR" "Failed to create objects directory"
        return 1
    fi
    
    # First, extract any images/media from carved files
    local carved_dir="$OUTPUT_DIR/carved"
    if [[ -d "$carved_dir" ]]; then
        # Find image files in carved directory
        local image_files
        image_files=$(find "$carved_dir" -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.bmp" \) 2>/dev/null | head -10)
        
        if [[ -n "$image_files" ]]; then
            while IFS= read -r img_file; do
                local basename
                basename=$(basename "$img_file")
                
                # exiftool
                if check_tool "exiftool"; then
                    run_command "exiftool \"$img_file\"" "$objects_dir/exif_$basename.txt" "EXIF data for $basename"
                fi
                
                # zsteg (if available)
                if check_tool "zsteg"; then
                    run_command "zsteg \"$img_file\"" "$objects_dir/zsteg_$basename.txt" "Steganography analysis for $basename"
                fi
            done <<< "$image_files"
        fi
    fi
    
    print_status "SUCCESS" "Media and steganography analysis completed"
}

# Function to run IDS analysis
run_ids_analysis() {
    local input_file="$1"
    
    print_status "INFO" "Starting IDS & anomaly detection..."
    
    # Zeek analysis
    if check_tool "zeek"; then
        local zeek_dir="$OUTPUT_DIR/zeek"
        if mkdir -p "$zeek_dir"; then
            local original_dir=$(pwd)
            if cd "$zeek_dir" 2>/dev/null; then
                run_command "zeek -r \"$input_file\"" "$zeek_dir/zeek.log" "Zeek network analysis"
                cd "$original_dir" || print_status "WARN" "Failed to return to original directory"
            else
                print_status "ERROR" "Failed to change to zeek directory"
            fi
        fi
    fi
    
    # Suricata analysis (if available)
    if check_tool "suricata"; then
        local suricata_dir="$OUTPUT_DIR/suricata"
        if mkdir -p "$suricata_dir"; then
            run_command "suricata -r \"$input_file\" -l \"$suricata_dir\"" "$suricata_dir/suricata.log" "Suricata IDS analysis"
        fi
    fi
    
    print_status "SUCCESS" "IDS analysis completed"
}

# Function to search for CTF keywords
search_ctf_keywords() {
    local input_file="$1"

    # Backwards compatibility wrapper: if single CTF_PATTERN passed via -c/--ctf
    if [[ -n "${CTF_PATTERN:-}" ]] && [[ ${#CTF_KEYWORDS[@]} -eq 0 ]]; then
        CTF_KEYWORDS+=("$CTF_PATTERN")
    fi
    
    if [[ ${#CTF_KEYWORDS[@]} -eq 0 ]]; then
        return 0
    fi
    
    print_status "INFO" "Starting CTF keyword search..."
    
    local misc_dir="$OUTPUT_DIR/misc"
    if ! mkdir -p "$misc_dir"; then
        print_status "ERROR" "Failed to create misc directory"
        return 1
    fi
    
    local ctf_results="$misc_dir/ctf_search_results.txt"
    
    {
        echo "=== CTF KEYWORD SEARCH RESULTS ==="
        echo "Keywords: ${CTF_KEYWORDS[*]}"
        echo "Search Date: $(date)"
        echo ""
    } > "$ctf_results"
    
    for keyword in "${CTF_KEYWORDS[@]}"; do
        echo "=== Searching for: $keyword ===" >> "$ctf_results"
        
        # Search in original PCAP using strings
        if check_tool "strings"; then
            echo "--- Strings search in PCAP ---" >> "$ctf_results"
            if strings "$input_file" | grep -i "$keyword" >> "$ctf_results" 2>/dev/null; then
                : # grep succeeded
            else
                echo "No matches found in strings" >> "$ctf_results"
            fi
        fi
        
        # Search in tshark payload
        if check_tool "tshark"; then
            echo "--- Payload search via tshark ---" >> "$ctf_results"
            if tshark -r "$input_file" -Y "frame contains \"$keyword\"" -T fields -e frame.number -e ip.src -e ip.dst -e data.text 2>/dev/null >> "$ctf_results"; then
                : # tshark succeeded
            else
                echo "No matches found in payload" >> "$ctf_results"
            fi
        fi
        
        # Search in carved files
        local carved_dir="$OUTPUT_DIR/carved"
        if [[ -d "$carved_dir" ]]; then
            echo "--- Search in carved files ---" >> "$ctf_results"
            if find "$carved_dir" -type f -exec grep -l "$keyword" {} \; 2>/dev/null >> "$ctf_results"; then
                : # find succeeded
            else
                echo "No matches found in carved files" >> "$ctf_results"
            fi
        fi
        
        # Search in stream files
        local streams_dir="$OUTPUT_DIR/streams"
        if [[ -d "$streams_dir" ]]; then
            echo "--- Search in reassembled streams ---" >> "$ctf_results"
            if find "$streams_dir" -type f -exec grep -l "$keyword" {} \; 2>/dev/null >> "$ctf_results"; then
                : # find succeeded
            else
                echo "No matches found in streams" >> "$ctf_results"
            fi
        fi
        
        echo "" >> "$ctf_results"
    done
    
    print_status "SUCCESS" "CTF keyword search completed"
}

# Function to generate timeline
generate_timeline() {
    local input_file="${1:-$INPUT_FILE}"
    local out_file="$OUTPUT_DIR/timeline/events.txt"
    mkdir -p "$OUTPUT_DIR/timeline"

    print_status "INFO" "Generating timeline (text)..."
    tshark -r "$input_file" -T fields \
           -e frame.number -e frame.time_epoch \
           -e ip.src -e ip.dst -e frame.len \
        | awk '{printf "%s | %s | %s -> %s | len=%s\n", $1, strftime("%Y-%m-%d %H:%M:%S", $2), $3, $4, $5}' \
        > "$out_file"

    print_status "SUCCESS" "Timeline generated: $out_file"
}

# Function to generate summary report
generate_summary() {
    print_status "INFO" "Generating summary report..."
    
    local summary_file="$OUTPUT_DIR/summary.txt"
    local index_file="$OUTPUT_DIR/index.md"
    
    {
        echo "PacketRoot Analysis Summary"
        echo "=========================="
        echo "Analysis Date: $(date)"
        echo "Input File: $INPUT_FILE"
        echo "Output Directory: $OUTPUT_DIR"
        echo ""
        echo "=== ANALYSIS MODULES RUN ==="
        echo "✓ File Metadata Analysis"
        echo "✓ Traffic Analysis"
        echo "✓ Protocol Extraction"
        echo "✓ Stream Reassembly"
        echo "✓ File Carving"
        echo "✓ Media & Steganography Analysis"
        echo "✓ IDS Analysis"
        [[ ${#CTF_KEYWORDS[@]} -gt 0 ]] && echo "✓ CTF Keyword Search"
        [[ "$TIMELINE_MODE" == "true" ]] && echo "✓ Timeline Generation"
        [[ "$RUN_ICMP" == "true" ]] && echo "✓ ICMP Analysis"
        [[ "$RUN_VOIP" == "true" ]] && echo "✓ VoIP Analysis"
        [[ "$RUN_ENTROPY" == "true" ]] && echo "✓ Entropy Analysis"
        [[ -n "$EXPORT_FORMAT" ]] && echo "✓ Export ($EXPORT_FORMAT)"
        echo ""
        
        if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
            echo "=== MISSING TOOLS ==="
            printf '%s\n' "${MISSING_TOOLS[@]}"
            echo ""
        fi
        
        echo "=== OUTPUT STRUCTURE ==="
        find "$OUTPUT_DIR" -type f 2>/dev/null | sort || echo "No files found"
        echo ""
        
        echo "=== QUICK STATS ==="
        if [[ -f "$OUTPUT_DIR/reports/io_stats.txt" ]]; then
            echo "Traffic Statistics:"
            head -10 "$OUTPUT_DIR/reports/io_stats.txt" 2>/dev/null || echo "No stats available"
        fi

                echo "" >> "$summary_file"
        echo "=== ENHANCED SUMMARY ===" >> "$summary_file"

        # Top 10 protocols (if protocol hierarchy exists)
        if [[ -f "$OUTPUT_DIR/reports/protocol_hierarchy.txt" ]]; then
            echo "Top protocol stats (top 10):" >> "$summary_file"
            head -n 20 "$OUTPUT_DIR/reports/protocol_hierarchy.txt" | sed -n '1,10p' >> "$summary_file"
        fi

        # Warnings / Errors counts (if any counters exist)
        if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
            echo "Missing required tools: ${MISSING_TOOLS[*]}" >> "$summary_file"
        fi
        
        if [[ ${#MISSING_OPTIONAL_TOOLS[@]} -gt 0 ]]; then
        echo "Missing optional tools: ${MISSING_OPTIONAL_TOOLS[*]}" >> "$summary_file"
        fi

         # Timeline info
        if [[ -f "$OUTPUT_DIR/timeline/events.txt" ]]; then
            echo "Timeline events: $(wc -l < "$OUTPUT_DIR/timeline/events.txt" 2>/dev/null || echo 0)" >> "$summary_file"
        fi

        # CTF hits
        if [[ -f "$OUTPUT_DIR/ctf/ctf_search_results.txt" ]]; then
            local ctf_hits
            ctf_hits=$(grep -i -c "." "$OUTPUT_DIR/ctf/ctf_search_results.txt" 2>/dev/null || echo 0)
            echo "CTF pattern hits: $ctf_hits" >> "$summary_file"
        fi
    } > "$summary_file"
    
    # Generate markdown index
    {
        echo "# PacketRoot Analysis Report"
        echo ""
        echo "**Analysis Date:** $(date)"
        echo "**Input File:** $INPUT_FILE"
        echo "**Output Directory:** $OUTPUT_DIR"
        echo ""
        echo "## Directory Structure"
        echo ""
        echo "- **reports/**: Traffic analysis and statistics"
        echo "- **protocols/**: Protocol-specific extractions"
        echo "- **objects/**: Media files and metadata"
        echo "- **streams/**: Reassembled network streams"
        echo "- **carved/**: Extracted files from traffic"
        echo "- **zeek/**: Zeek network analysis logs"
        echo "- **suricata/**: Suricata IDS alerts"
        echo "- **misc/**: Miscellaneous analysis results"
        [[ -d "$OUTPUT_DIR/icmp_analysis" ]] && echo "- **icmp_analysis/**: ICMP traffic analysis"
        [[ -d "$OUTPUT_DIR/voip_analysis" ]] && echo "- **voip_analysis/**: VoIP traffic analysis"
        [[ -d "$OUTPUT_DIR/exports" ]] && echo "- **exports/**: Exported data files"
        [[ -d "$OUTPUT_DIR/timeline" ]] && echo "- **timeline/**: Interactive timeline visualization"
        echo ""
        echo "## Key Files"
        echo ""
        echo "- \`summary.txt\`: Complete analysis summary"
        echo "- \`missing_tools.txt\`: List of unavailable tools"
        echo ""
        [[ ${#CTF_KEYWORDS[@]} -gt 0 ]] && echo "- \`misc/ctf_search_results.txt\`: CTF keyword search results"
        [[ "$TIMELINE_MODE" == "true" ]] && echo "- \`misc/timeline.txt\`: Chronological event timeline"
        [[ -f "$OUTPUT_DIR/timeline/interactive_timeline.html" ]] && echo "- \`timeline/interactive_timeline.html\`: Interactive timeline visualization"
    } > "$index_file"
    
    # Log missing tools
    if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
        printf '%s\n' "${MISSING_TOOLS[@]}" > "$OUTPUT_DIR/missing_tools.txt"
    fi
    
    print_status "SUCCESS" "Summary report generated"
}

# Function to show tool versions
show_tools() {
    print_banner "Installed Tools & Versions" "$CYAN"
    
    local tools=("tshark" "tcpflow" "foremost" "exiftool" "zeek" "binwalk" "bulk_extractor" "suricata" "zsteg" "strings")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version
            version=$($tool --version 2>&1 | head -1 || echo "Version unknown")
            print_status "SUCCESS" "$tool: $version"
        else
            print_status "ERROR" "$tool: Not installed"
        fi
    done
}

# Function to display usage with color and formatting (ENHANCED)
usage() {
    local cmd="${0##*/}"
    
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║ ${WHITE}PacketRoot v$VERSION - PCAP/PCAPNG Forensic & CTF Analysis Toolkit${CYAN}            ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${YELLOW}USAGE:${NC}                                                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}$cmd ${YELLOW}<pcap_file>${NC} [options]${CYAN}                                                    ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${YELLOW}OPTIONS:${NC}                                                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-ctf ${YELLOW}<keyword>${NC}     Search for CTF keywords (can be used multiple times)${CYAN}         ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-proto ${YELLOW}<protocol>${NC}  Focus on specific protocol (can be used multiple times)${CYAN}      ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-quick${NC}             Minimal scan (metadata, endpoints, basic stats)${CYAN}               ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-deep${NC}              Maximum analysis (all modules including advanced carving)${CYAN}      ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-timeline${NC}          Generate chronological event timeline${CYAN}                        ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-stats${NC}             Only generate traffic statistics${CYAN}                              ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-meta${NC}              Only extract file metadata${CYAN}                                    ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-export ${YELLOW}<fmt>${NC}     Export results (json|csv|xml)${CYAN}                               ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-icmp${NC}              Run detailed ICMP analysis${CYAN}                                   ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-voip${NC}              Run VoIP (RTP/SIP) analysis${CYAN}                                  ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-entropy${NC}           Run entropy analysis for encrypted data${CYAN}                     ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-parallel${NC}          Enable parallel processing${CYAN}                                  ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-config ${YELLOW}<file>${NC}   Use custom configuration file${CYAN}                             ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-tools${NC}             Show installed tools and versions${CYAN}                             ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}-h, --help${NC}         Show this help message${CYAN}                                       ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${YELLOW}EXAMPLES:${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}$cmd${NC} capture.pcap${CYAN}                                                         ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}$cmd -ctf${NC} \"FLAG{\" capture.pcap${CYAN}                                              ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}$cmd -export${NC} json capture.pcap${CYAN}                                              ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}$cmd -icmp -voip${NC} capture.pcap${CYAN}                                               ║${NC}"
    echo -e "${CYAN}║${NC}    ${GREEN}$cmd -deep -parallel -timeline${NC} capture.pcap${CYAN}                                 ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${YELLOW}SUPPORTED FORMATS:${NC}                                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • PCAP (.pcap)${CYAN}                                                             ║${NC}"
    echo -e "${CYAN}║${NC}    • PCAPNG (.pcapng)${CYAN}                                                         ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${YELLOW}OUTPUT:${NC}                                                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    Results are saved to: ${GREEN}output/<filename>_<timestamp>/${NC}${CYAN}                             ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}    ${WHITE}GitHub: https://github.com/sarveshvetrivel/packetroot${NC}${CYAN}                             ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}\n"
}

# Function to check system requirements
check_requirements() {
    # Check Bash version
    local bash_version
    bash_version=$(bash --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    if [[ "$(printf "%s\n" "$MINIMUM_BASH_VERSION" "$bash_version" | sort -V | head -n1)" != "$MINIMUM_BASH_VERSION" ]]; then
        echo -e "${RED}ERROR: Bash version $MINIMUM_BASH_VERSION or higher is required (found $bash_version)${NC}" >&2
        return 3
    fi

    # Check for required tools
    local required_tools=("tshark" "capinfos" "editcap" "mergecap" "dumpcap" "file")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}ERROR: Missing required tools: ${missing_tools[*]}${NC}" >&2
        echo -e "Please install the missing tools to continue" >&2
        return 3
    fi
    
    # Check TShark version
    local tshark_version
    tshark_version=$(tshark -v 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -n1)
    if [[ "$(printf "%s\n" "$MINIMUM_TSHARK_VERSION" "$tshark_version" | sort -V | head -n1)" != "$MINIMUM_TSHARK_VERSION" ]]; then
        echo -e "${YELLOW}WARNING: TShark version $MINIMUM_TSHARK_VERSION or higher is recommended (found $tshark_version)${NC}" >&2
    fi
    
    # Check disk space (at least 1GB free)
    local min_disk_space=1000000  # 1GB in KB
    local free_space
    if command -v df &>/dev/null; then
        free_space=$(df -k --output=avail "$SCRIPT_DIR" 2>/dev/null | tail -n1)
        
        if [[ $free_space -lt $min_disk_space ]]; then
            echo -e "${YELLOW}WARNING: Low disk space (${free_space}KB free). At least 1GB is recommended.${NC}" >&2
        fi
    fi
    
    return 0
}

# Main function (ENHANCED with new options)
main() {
    # Check system requirements first
    if ! check_requirements; then
        exit $?
    fi
    
    # Load configuration and plugins at startup
    load_config
    load_plugins
    
    # Initialize variables
    local input_file=""
    local quick_mode=false
    local deep_mode=false
    local show_help=false
    local show_tools_flag=false
    local stats_only=false
    local meta_only=false
    
    # Parse command line arguments (ENHANCED)
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--ctf)
                if [[ -n "${2:-}" ]]; then
                    # allow both -ctf KEYWORD and -c KEYWORD compatibility
                    CTF_KEYWORDS+=("$2"
                    )
                    CTF_PATTERN="$2"
                    shift 2
                else
                    print_status "ERROR" "Option -c/--ctf requires a keyword argument"
                    exit 2
                fi
                ;;
            -proto)
                if [[ -n "${2:-}" ]]; then
                    PROTOCOLS+=("$2")
                    shift 2
                else
                    print_status "ERROR" "Option -proto requires a protocol argument"
                    exit 2
                fi
                ;;
            -export)
                if [[ -n "${2:-}" ]]; then
                    EXPORT_FORMAT="$2"
                    shift 2
                else
                    print_status "ERROR" "Option -export requires a format argument (json|csv|xml)"
                    exit 2
                fi
                ;;
            -config)
                if [[ -n "${2:-}" ]]; then
                    CONFIG_FILE="$2"
                    shift 2
                else
                    print_status "ERROR" "Option -config requires a file path"
                    exit 2
                fi
                ;;
            -parallel)
                ENABLE_PARALLEL="true"
                shift
                ;;
            -icmp)
                RUN_ICMP="true"
                shift
                ;;
            -voip)
                RUN_VOIP="true"
                shift
                ;;
            -entropy)
                RUN_ENTROPY="true"
                shift
                ;;
             -q|--quick)
                quick_mode=true
                MODE="quick"
                shift
                ;;
            -d|--deep)
                deep_mode=true
                MODE="deep"
                shift
                ;;
            -i|--interactive)
                INTERACTIVE_MODE="true"
                shift
                ;;
            -timeline)
                TIMELINE_MODE="true"
                shift
                ;;
            -stats)
                stats_only=true
                shift
                ;;
            -meta)
                meta_only=true
                shift
                ;;
            -tools)
                show_tools_flag=true
                shift
                ;;
            -o|--output)
                if [[ -n "${2:-}" ]]; then
                    CUSTOM_OUTPUT_DIR="$2"
                    shift 2
                else
                    print_status "ERROR" "Option -o/--output requires a directory path"
                    exit 2
                fi
                ;;
            -h|--help)
                show_help=true
                shift
                ;;
            -v|--version)
                echo "PacketRoot v$VERSION (Released: $RELEASE_DATE)"
                exit 0
                ;;
            -*)
                print_status "ERROR" "Unknown option: $1"
                usage
                exit 2
                ;;
            *)
                if [[ -z "$input_file" ]]; then
                    input_file="$1"
                else
                    print_status "ERROR" "Multiple input files specified"
                    exit 2
                fi
                shift
                ;;
        esac
    done
    
    # Handle help and tools flags
    if [[ "$show_help" == true ]]; then
        usage
        exit 0
    fi
    
    if [[ "$show_tools_flag" == true ]]; then
        show_tools
        exit 0
    fi
    
    # Check if input file is provided for analysis
    if [[ -z "$input_file" ]]; then
        print_status "ERROR" "No input file specified"
        usage
        exit 2
    fi
    
    if [[ ! -f "$input_file" ]]; then
        print_status "ERROR" "Input file does not exist: $input_file"
        exit 4
    fi
    
    if [[ ! -r "$input_file" ]]; then
        print_status "ERROR" "Cannot read input file (permission denied): $input_file"
        exit 5
    fi
    
    # Convert to absolute path
    INPUT_FILE="$(realpath "$input_file")"
    
    # Display banner with analysis info - ONLY ONCE AT THE START
    local analysis_type="Full Analysis"
    [[ "$quick_mode" == "true" ]] && analysis_type="Quick Analysis"
    [[ "$deep_mode" == "true" ]] && analysis_type="Deep Analysis"
    [[ "$stats_only" == "true" ]] && analysis_type="Statistics Only"
    [[ "$meta_only" == "true" ]] && analysis_type="Metadata Only"
    
    local banner_message="${analysis_type} - $(basename "$INPUT_FILE")"
    print_banner "$banner_message" "$WHITE"
    print_status "INFO" "Input file: $INPUT_FILE"
    
    # Create output directory structure
    if ! create_output_structure "$INPUT_FILE"; then
        print_status "ERROR" "Failed to create output structure"
        exit 1
    fi
    
    # Run analysis modules based on mode
    local analysis_exit_code=0
    
    # If interactive flag set, hand control to menu
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        # Ensure INPUT_FILE set
        INPUT_FILE="${input_file:-$INPUT_FILE}"
        interactive_menu "${INPUT_FILE}"
        # After interactive returns, generate summary
        generate_summary
        exit 0
    fi

    # Non-interactive normal execution follows...

    if [[ "$meta_only" == "true" ]]; then
        extract_metadata "$INPUT_FILE" || analysis_exit_code=$?
    elif [[ "$stats_only" == "true" ]]; then
        analyze_traffic "$INPUT_FILE" || analysis_exit_code=$?
    elif [[ "$quick_mode" == "true" ]]; then
        extract_metadata "$INPUT_FILE" || analysis_exit_code=$?
        analyze_traffic "$INPUT_FILE" || analysis_exit_code=$?
        extract_protocols "$INPUT_FILE" || analysis_exit_code=$?
    else
        # Full analysis (default) or deep mode
        extract_metadata "$INPUT_FILE" || analysis_exit_code=$?
        analyze_traffic "$INPUT_FILE" || analysis_exit_code=$?
        extract_protocols "$INPUT_FILE" || analysis_exit_code=$?
        reassemble_streams "$INPUT_FILE" || analysis_exit_code=$?
        carve_files "$INPUT_FILE" || analysis_exit_code=$?
        analyze_media_steg "$INPUT_FILE" || analysis_exit_code=$?
        run_ids_analysis "$INPUT_FILE" || analysis_exit_code=$?
        
        # CTF keyword search if keywords provided
        if [[ ${#CTF_KEYWORDS[@]} -gt 0 ]]; then
            search_ctf_keywords "$INPUT_FILE" || analysis_exit_code=$?
            local out_file="$OUTPUT_DIR/ctf/ctf_search_results.txt"
            mkdir -p "$OUTPUT_DIR/ctf"
        fi
        
        # Timeline if requested
        if [[ "$TIMELINE_MODE" == "true" ]]; then
            generate_timeline "$INPUT_FILE" || analysis_exit_code=$?
        fi
    fi
    
    # NEW: Run additional analysis modules
    if [[ "$RUN_ICMP" == "true" ]] || [[ "$deep_mode" == "true" ]]; then
        analyze_icmp "$INPUT_FILE" || analysis_exit_code=$?
    fi
    
    if [[ "$RUN_VOIP" == "true" ]] || [[ "$deep_mode" == "true" ]]; then
        analyze_voip "$INPUT_FILE" || analysis_exit_code=$?
    fi
    
    # Run additional protocol analysis
    if [[ "$deep_mode" == "true" ]]; then
        analyze_additional_protocols "$INPUT_FILE" || analysis_exit_code=$?
    fi
    
    # Run entropy analysis if requested or in deep mode
    if [[ "$RUN_ENTROPY" == "true" ]] || [[ "$deep_mode" == "true" ]]; then
        analyze_entropy || analysis_exit_code=$?
    fi
    
    # Export results if format specified
    if [[ -n "$EXPORT_FORMAT" ]]; then
        export_results "$EXPORT_FORMAT" || analysis_exit_code=$?
    fi
    
    # Run parallel analyses if enabled
    if [[ "$ENABLE_PARALLEL" == "true" ]]; then
        run_parallel || analysis_exit_code=$?
    fi
    
    # Generate summary report
    generate_summary
    
    # Final status
    print_status "SUCCESS" "Results saved to: $OUTPUT_DIR"
    print_status "INFO" "Check index.md for a summary of findings"
    
    if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
        print_status "WARN" "Some tools were missing. Install dependencies to enable full functionality:"
        for tool in "${MISSING_TOOLS[@]}"; do
            print_status "INFO" "  - $tool"
        done
    fi
    
    # Exit with appropriate code
    if [[ $analysis_exit_code -eq 10 ]]; then
        print_status "WARN" "Analysis completed but security issues were detected"
        exit 10
    elif [[ $analysis_exit_code -ne 0 ]]; then
        print_status "WARN" "Analysis completed with some errors (exit code: $analysis_exit_code)"
        exit $analysis_exit_code
    fi
    
    find "$OUTPUT_DIR" -type d -empty -delete  # Clean up empty dirs

    [[ -d "$OUTPUT_DIR/timeline" && "$(ls -A "$OUTPUT_DIR/timeline")" ]] && \
        print_status "INFO" "Timeline: $OUTPUT_DIR/timeline"

    [[ -d "$OUTPUT_DIR/ctf" && "$(ls -A "$OUTPUT_DIR/ctf")" ]] && \
        print_status "INFO" "CTF results: $OUTPUT_DIR/ctf"

    exit 0
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

