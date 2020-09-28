sudo ovs-ofctl del-groups -O OpenFlow13 s1
sudo ovs-ofctl del-groups -O OpenFlow13 s2
sudo ovs-ofctl del-groups -O OpenFlow13 s3
sudo ovs-ofctl del-flows -O OpenFlow13 s1
sudo ovs-ofctl del-flows -O OpenFlow13 s2
sudo ovs-ofctl del-flows -O OpenFlow13 s3
./show_switch_rules.sh