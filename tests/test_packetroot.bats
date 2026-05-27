#!/usr/bin/env bats

setup() {
    # Ensure the script is executable
    chmod +x ./packetroot.sh
    
    # Create a dummy pcap file for basic tests
    mkdir -p tests/test_data
    touch tests/test_data/dummy.pcap
}

teardown() {
    # Clean up test output directories
    rm -rf output/dummy_*
    rm -rf tests/test_data
}

@test "packetroot.sh shows help menu" {
    run ./packetroot.sh --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "USAGE:" ]]
}

@test "packetroot.sh fails without input file" {
    run ./packetroot.sh
    [ "$status" -eq 2 ]
    [[ "$output" =~ "No input file specified" ]]
}

@test "packetroot.sh rejects non-existent input file" {
    run ./packetroot.sh "does_not_exist.pcap"
    [ "$status" -eq 4 ]
    [[ "$output" =~ "Input file does not exist" ]]
}

@test "packetroot.sh checks tool versions with -tools" {
    run ./packetroot.sh -tools
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Installed Tools & Versions" ]]
}

@test "packetroot.sh executes metadata extraction mode" {
    run ./packetroot.sh -meta tests/test_data/dummy.pcap
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Starting file metadata analysis" ]]
}

@test "packetroot.sh sanitizes output directory" {
    run ./packetroot.sh -meta -o "/tmp/safe_dir" tests/test_data/dummy.pcap
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Output directory created: /tmp/safe_dir" ]]
    rm -rf /tmp/safe_dir
}
