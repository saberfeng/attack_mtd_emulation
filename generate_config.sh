# Generate configuration file
#                               num_hosts num_ports port_range  mtd_time controller scan_type scan_open_ports single_port interval_scan
python2 ./Ryu/generate_config.py 5         10        50000-50999 3600     FRVM       sS        1               0           0
