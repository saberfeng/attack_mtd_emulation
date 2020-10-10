
def run():
    ports_set = set()
    with open("vul_ports", "r") as f:
        lines = f.readlines()
        for line in lines:
            address = line.split()[3]
            ports_set.add(int(address.split(":")[1]))
    port_str = ""
    port_list = list(ports_set)
    port_list = sorted(port_list)
    for port in port_list:
        port_str += str(port) + ",\n"
    print(port_str)


if __name__ == "__main__":
    run()