# infotecs_test_task
The program must implement the functionality of classifying network packets; to do this, it must do the following:

1) Using the libpcap library (or another one of the developer’s choice), read packets from a pcap file, including the ability to capture packets from the network interface.

2) Select from them the IP packet headers and TCP|UDP headers.

3) Read IP addresses and ports from the selected headers.

4) Classify each packet into a flow (a collection of packets from IP address No. 1 to IP address No. 2 with a unique port combination).

5) In each stream, count the number of packets and the number of bytes transferred.

6) After reading all the packages, information about all allocated streams must be written to a CSV file.

Program Note #1: Only IPv4 packets need to be classified.
