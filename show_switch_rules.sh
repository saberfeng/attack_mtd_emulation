echo "-------------s1:--------------"
echo "---groups:"
sudo ovs-ofctl dump-groups -O OpenFlow13 s1
echo "---flows:"
sudo ovs-ofctl dump-flows -O OpenFlow13 s1
echo "-------------s2:--------------"
echo "---groups:"
sudo ovs-ofctl dump-groups -O OpenFlow13 s2
echo "---flows:"
sudo ovs-ofctl dump-flows -O OpenFlow13 s2
echo "-------------s3:--------------"
echo "---groups:"
sudo ovs-ofctl dump-groups -O OpenFlow13 s3
echo "---flows:"
sudo ovs-ofctl dump-flows -O OpenFlow13 s3
