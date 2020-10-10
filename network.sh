
# bash -c "PYTHONPATH=. ryu-manager ./Ryu/FRVM_controller.py" &
# echo
# sleep .5 # Wait for Ryu to setup

# sudo python3 ./Mininet/one_subnet.py
sudo python3 ./Mininet/network_with_attacker.py # Start the Mininet network
