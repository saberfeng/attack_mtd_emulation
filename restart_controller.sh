# fuser -k 6653/tcp
./clear_all_rules.sh
sudo docker exec mn.r1 ip -s -s neigh flush all
./controller.sh