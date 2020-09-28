sudo mn --clean > /dev/null # Perform a Mininet clean
sudo kill -s KILL $(lsof -t -i:6653) > /dev/null # Kill Ryu application
