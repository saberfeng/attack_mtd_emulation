sleep 31 &
BACK_PID_1=$!
sleep 32 &
BACK_PID_2=$!

wait $BACK_PID_1 $BACK_PID_2
timeout 60 nmap --sS -p 1-9000 -oX nmap_Time60_ScansS_Port1-9000_34_2.xml  --exclude 10.0.0.1,10.0.0.2 -Pn --max-retries 0 --max-rtt-timeout 1000ms 10.0.0.0/22


