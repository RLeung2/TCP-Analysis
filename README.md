# TCP-Analysis
The code uses the dpkt package to read the pcap file into a series of bytes.

It looks at the pcap file in the different flows by using a while loop to reiterate on the file until
there are no more flows to check.

A set is used to keep track of the source ports to make sure the same flow isn’t checked more
than once.

The code checks the flag of each packet to see if it’s a SYN. If so, add 1 to the flow count and
analyze that flow.

In each flow:
The sequence number of the SYN is used to find the relative sequence numbers of future sent
packets by subtraction.

The sequence number of the SYN/ACK is used to find the relative acknowledgement numbers of
future sent packets by subtraction.

A print count is used to only print the sent packets of the first 2 transactions.

The receiver window size of a packet is calculated by taking 2 to the power of the window scale
in the SYN packet and multiplying it by the window in the current packet.

Each sent packet is recorded in a count as well as the number of bytes in each packet in order to
calculate throughput and loss rate later.

The total time used to calculate throughput is found by taking the time at receiving the FIN and
subtracting that by the time the first data packet was sent.

Loss packets are counted if sequence number is repeated in a sent packet. This indicates
retransmission. Out-Of-Order packets were counted as retransmitted packets.

Loss rate is calculated by dividing the loss packets by the total sent packets.

A CWND dictionary and count is used to keep track of the first 5 CWNDs. It maps the seq of the
first 5 sent packets to an integer counting the total bytes of packets sent that occur after the sent
packet until the ack is received.

All answers to the questions in the assignment are printed out by the program
