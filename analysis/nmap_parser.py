from libnmap.parser import NmapParser
import json

path1 = "nmap_outputs/simple_switch_13/"
path2 = "nmap_outputs/FRVM/"
intervals = [100, 200, 300, 400, 500, 600]

# nmap_report = NmapParser.parse_fromfile(path2 + "nmap_Time600_ScansS_Port1-9000_49.xml")
# print("Nmap scan summary: {0}".format(nmap_report.summary))

# with open("parse_result", "w") as f:
#     for interval in intervals:
#         f.write("Interval:{}\n".format(interval))
#         for i in range(0, 50):
#             file_name = "nmap_Time{}_ScansS_Port1-9000_{}.xml".format(interval, i)
#             nmap_report = NmapParser.parse_fromfile(path2 + file_name)

#             hosts_num = len(nmap_report.hosts)
#             ports_num = 0
#             for host in nmap_report.hosts:
#                 ports_num += len(host.get_open_ports())
#             f.write("{},{}\n".format(hosts_num, ports_num))
#         f.write("\n\n")

results_dict = {}

with open("parse_result", "w") as f:
    for interval in intervals:
        f.write("Interval:{}\n".format(interval))
        total_port = 0
        for i in range(0, 50):
            file_name = "nmap_Time{}_ScansS_Port1-9000_{}.xml".format(interval, i)
            with open(path2 + file_name) as input_file:
                content = input_file.read()
                port_count = content.count('state="open"')
                total_port += port_count
            f.write("{}\n".format(port_count))
        f.write("total ports discovered:{}\n".format(total_port))
        results_dict["interval_{}".format(interval)] = total_port
        f.write("\n\n")
    f.write(json.dumps(results_dict, indent=4))
