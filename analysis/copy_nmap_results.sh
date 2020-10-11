docker exec mn.r1 sh -c "mkdir nmap_outputs"
docker exec mn.r1 sh -c "mv *.xml nmap_outputs"
# docker cp mn.r1:/root/nmap_outputs/. ./nmap_outputs/simple_switch_13
docker cp mn.r1:/root/nmap_outputs/. ./nmap_outputs/FRVM