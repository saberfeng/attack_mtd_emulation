docker exec mn.r1 sh -c "mkdir nmap_outputs"

while true
do 
    docker exec mn.r1 sh -c "mv *.xml nmap_outputs"
    docker cp mn.r1:/root/nmap_outputs/. ./nmap_outputs/tmp
    now=$(date +"%T")
    echo "Copied : $now"
    sleep 2m
done 
# # docker cp mn.r1:/root/nmap_outputs/. ./nmap_outputs/simple_switch_13
