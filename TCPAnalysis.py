import dpkt


def analysis_pcap_tcp(file: str):
    flow_count = 0
    port_set = {-1}  # keeps track of ports/flows
    flows_done = False

    while not flows_done:
        flows_done = True
        print_count = 1  # counter for packet printing
        print_amount = 2  # number of sent transactions you want to print information for each flow
        byte_count = 0  # number of bytes sent to calculate throughput later
        sent_packets = 0  # counter for number of sent packets
        current_port = None
        seq_set = {-1}
        retransmission_count = 0

        cwnd_dict ={}  # dictionary for cwnd calulations
        cwnd_list = []  # list for final cwnd byte counts
        cwnd_count = 1  # counter for cwnds to print
        cwnd_amount = 5  # number of cwnds you want
        cwnd_pop_count = 1  # counter to pop when acks are received

        a = open(file, 'rb')
        pcap = dpkt.pcap.Reader(a)

        for timestamp, buf in pcap:
            ethernet = dpkt.ethernet.Ethernet(buf)
            ip = ethernet.data
            tcp = ip.data

            # Don't check packet if flow was already looked at
            if (tcp.sport in port_set) | (tcp.dport in port_set):
                continue

            # SYN flow start check if there is no current flow being looked at
            if (tcp.flags == 2) & (current_port == None):
                flows_done = False  # found another flow to analyze
                flow_count += 1
                print("---------- Flow " + str(flow_count) + ": ----------")

                current_port = tcp.sport  # current flow being analyzed
                relative_seq_dif = tcp.seq  # used to find relative sequence numbers
                start_time = timestamp
                window_scale = 2**buf[73] # used to calculate receiver window size

                continue

            # Sender check
            if tcp.sport == current_port:
                # Sender ACK check (does not count in throughput)
                if len(buf) == 66:
                    continue

                if tcp.seq in seq_set:
                    retransmission_count += 1
                else:
                    seq_set.add(tcp.seq)

                byte_count += len(buf)  # add length to total byte count
                sent_packets += 1

                # Start printing desired transactions
                if print_count <= print_amount:

                    if (len(buf) > 66) & (tcp.flags != 2) & (tcp.flags != 18):
                        relative_seq = tcp.seq - relative_seq_dif
                        relative_ack = tcp.ack - relative_ack_dif
                        print("Transaction " + str(print_count) + " SEQ: " + str(relative_seq))
                        print("Transaction " + str(print_count) + " ACK: " + str(relative_ack))
                        print("Transaction " + str(print_count) + " receiver window: " + str(tcp.win * window_scale) + " bytes") # Receiver window calculation
                        print()
                        print_count += 1

                # Start counting bytes for cwnd calculations
                if cwnd_count <= cwnd_amount:

                    if (len(buf) > 66) & (tcp.flags != 2) & (tcp.flags != 18):
                        cwnd_dict[cwnd_count] = 0  # seq number, byte count
                        cwnd_count += 1

                for x in cwnd_dict:
                    cwnd_dict[x] += len(buf)  # add bytes of current packet to cwnd counts in dictionary


            # Receive check
            if tcp.dport == current_port:
                # SYN/ACK check
                if tcp.flags == 18:
                    relative_ack_dif = tcp.seq  # used to find relative ack numbers

                elif cwnd_dict:
                    cwnd = cwnd_dict.pop(cwnd_pop_count)
                    cwnd_list.append(cwnd)
                    cwnd_pop_count += 1

                # FIN check
                if tcp.flags == 17:
                    port_set.add(current_port)  # add to set so it doesn't get looked at again
                    end_time = timestamp
                    total_time = end_time - start_time  # used to calculate throughput
                    throughput = float(byte_count / total_time)

                    print("Total data sent: " + str(byte_count) + " bytes")
                    print("Flow time elapsed: " + str(total_time) + " seconds")
                    print("Throughput: " + str(throughput) + " bytes per second")
                    print()
                    print("Lost packets: " + str(retransmission_count))
                    print("Sent packets: " + str(sent_packets))
                    print("Loss rate: " + str(retransmission_count / sent_packets))
                    print()
                    print("First 5 CWNDs: ")
                    for i in cwnd_list:
                        print(str(i) + " bytes")

                    print()
                    print()
                    break

    print("Flow Count: " + str(flow_count))


analysis_pcap_tcp("assignment3.pcap")



