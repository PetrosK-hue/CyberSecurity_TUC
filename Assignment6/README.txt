###################################################################

[ASSIGNMENT 6] Network Traffic Monitoring in C (Packet Capture Library)
             KATSIBAS PETROS(2016030038)

###################################################################
###################################################################
MAKE FILE:

    make all            # gcc project
    make clean          # Clean executable demo.
    make run            # Runs program and captures packets from our file .pcap file.
                         (./monitor -r test_pcap_5mins.pcap )   
###################################################################

## Summary

In this assignment, we created a monitor tool to capture Network Traffic using the 
Packet Capture Library. We used offline capture function ( pcap_open_offline() ) as we have already given a 
.pcap file to test our demo and with pcap_loop() function and our callback function gotPacket() we managed to
parse every packet (TCP, UDP or OTHER) included in file and decode it in order to show/print its information.

### Answer 9th Q.

Yes,we can tell if a incoming TCP packet is a retransmission, as networks (Server and Client) uses a combination of 
acknowledgment parameters for every conversation/ packet traffic. When server receives a package he increases his 
acknowledgement parameter by the received payload len and when sends a packet back to client, a check happens in order
to compare the sequence number. If parameters differ, we will have a retransmitted package, so network's functionality 
is correct and stable. 

### Answer 10th Q.

UDP doesn't care for packet loss, therefore we are NOT able to tell if an incoming UDP packer is a retransmission. If an 
UDP packet arrives and has a bad checksum, it is simply dropped. Neither the sender of the packet is informed about this, 
nor the recipient is informed. 

gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0

