#!/usr/bin/env bash
# --------------------------------------
# Executes a Ryu controller, for Ethernet-level  routing, and Mininet virtualised network. An outside attacker will scan
# the protected network with the specified port scanning technique.
# @param mtd_time: Specifies an address mutation interval.
# @param scan_type: Specifies a port scanning technique using the Nmap tags of the form sS, sT, sU, ...
# @param ports_discovered: Boolean specifying only scan for open ports. Imitates the rediscovery of hosts.
# @param single_port: Boolean specifying only scan for a single port within the range of 50000-50999
# @param MTD_interval_scan: Specifies time restriction for the scan. Used for the partial scans.
# --------------------------------------

# Clean and kill applications before executing
sudo mn --clean > /dev/null # Perform a Mininet clean
sudo kill -s KILL $(lsof -t -i:6653) > /dev/null # Kill Ryu application

# Generate configuration file
#                               num_hosts num_ports port_range  mtd_time controller scan_type scan_open_ports single_port interval_scan
python ./Ryu/generate_config.py 5         10        50000-50999 $1       FRVM       $2        $3              $4          $5
sleep 1 # Wait for file to be generated

bash -c "PYTHONPATH=. ryu-manager ./Ryu/FRVM_controller.py" &
echo
sleep .5 # Wait for Ryu to setup
sudo ./Mininet/networks.py NmapNetwork # Start the Mininet network

# rm -f ./Scans/FRVM/*.xml
#           interval scan_type ports_discovered  single_port interval_scan
# ./FRVM.sh 100       sS       1                 1            0
# ./FRVM.sh 100       sS       1                 1            30