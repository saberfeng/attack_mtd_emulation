import socket
import sys

class UDP_Client:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
    
    def run(self):
        msgFromClient = "Hello UDP Server"
        bytesToSend = str.encode(msgFromClient)
        bufferSize = 1024

        # Create a UDP socket at client side
        UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        # Send to server using created UDP socket
        UDPClientSocket.sendto(bytesToSend, (self.server_ip, self.server_port))

        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        msg = "Message from Server {}".format(msgFromServer[0])
        print(msg)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        udp_client = UDP_Client(sys.argv[1], int(sys.argv[2]))
        udp_client.run()