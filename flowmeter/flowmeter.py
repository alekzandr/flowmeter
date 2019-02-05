from scapy.all import *
import pandas as pd
import numpy as np
import binascii
from multiprocessing import Pool

class Flowmeter:

    """
    This is the flowmeter class. It's purpose is to
    take in a pcap file and output a csv file
    containing 84 features to be used in machine
    learning applications.
    """
    
    def __init__(self, pcap=None):
        
        """
        Args:
            pcap (str): OS location to a pcap file.
        """

        self._pcap = rdpcap(pcap)
        self.columns = [
            "flow",                 # Index
            "src",                  # Source IP
            "src_port",             # Source port
            "dst",                  # Destination IP
            "dst_port",             # Destination port
            "feduration",	        # Duration of the flow in Microsecond
            "total_fpackets",	    # Total packets in the forward direction
            "total_bpackets",	    # Total packets in the backward direction
            "total_fpktl",	        # Total size of packet in forward direction
            "total_bpktl",	        # Total size of packet in backward direction
            "min_fpktl",	        # Minimum size of packet in forward direction
            "min_bpktl",	        # Minimum size of packet in backward direction
            "max_fpktl",            # Maximum size of packet in forward direction
            "max_bpktl",	        # Maximum size of packet in backward direction
            "mean_fpktl",	        # Mean size of packet in forward direction
            "mean_bpktl",	        # Mean size of packet in backward direction
            "std_fpktl",	        # Standard deviation size of packet in forward direction
            "std_bpktl",	        # Standard deviation size of packet in backward direction
            "total_fiat",	        # Total time between two packets sent in the forward direction
            "total_biat",	        # Total time between two packets sent in the backward direction
            "min_fiat", 	        # Minimum time between two packets sent in the forward direction
            "min_biat", 	        # Minimum time between two packets sent in the backward direction
            "max_fiat", 	        # Maximum time between two packets sent in the forward direction
            "max_biat", 	        # Maximum time between two packets sent in the backward direction
            "mean_fiat",	        # Mean time between two packets sent in the forward direction
            "mean_biat",	        # Mean time between two packets sent in the backward direction
            "std_fiat", 	        # Standard deviation time between two packets sent in the forward direction
            "std_biat", 	        # Standard deviation time between two packets sent in the backward direction
            "fpsh_cnt", 	        # Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
            "bpsh_cnt", 	        # Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)
            "furg_cnt", 	        # Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
            "burg_cnt", 	        # Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)
            "total_fhlen",	        # Total bytes used for headers in the forward direction
            "total_bhlen",	        # Total bytes used for headers in the forward direction
            "fPktsPerSecond",	    # Number of forward packets per second
            "bPktsPerSecond",	    # Number of backward packets per second
            "flowPktsPerSecond",	# Number of flow packets per second
            "flowBytesPerSecond",	# Number of flow bytes per second
            "min_flowpktl", 	    # Minimum length of a flow
            "max_flowpktl",	        # Maximum length of a flow
            "mean_flowpktl",	    # Mean length of a flow
            "std_flowpktl", 	    # Standard deviation length of a flow
            "min_flowiat",	        # Minimum inter-arrival time of packet
            "max_flowiat",	        # Maximum inter-arrival time of packet
            "mean_flowiat",	        # Mean inter-arrival time of packet
            "std_flowiat",	        # Standard deviation inter-arrival time of packet
            "flow_fin", 	        # Number of packets with FIN
            "flow_syn", 	        # Number of packets with SYN
            "flow_rst", 	        # Number of packets with RST
            "flow_psh", 	        # Number of packets with PUSH
            "flow_ack", 	        # Number of packets with ACK
            "flow_urg", 	        # Number of packets with URG
            "flow_cwr", 	        # Number of packets with CWE
            "flow_ece", 	        # Number of packets with ECE
            "downUpRatio",	        # Download and upload ratio
            "avgPacketSize",	    # Average size of packet
            "fAvgSegmentSize",	    # Average size observed in the forward direction
            "fAvgBytesPerBulk",	    # Average number of bytes bulk rate in the forward direction
            "fAvgPacketsPerBulk",	# Average number of packets bulk rate in the forward direction
            "fAvgBulkRate", 	    # Average number of bulk rate in the forward direction
            "bAvgSegmentSize",	    # Average size observed in the backward direction
            "bAvgBytesPerBulk",	    # Average number of bytes bulk rate in the backward direction
            "bAvgPacketsPerBulk",	# Average number of packets bulk rate in the backward direction
            "bAvgBulkRate", 	    # Average number of bulk rate in the backward direction
            "label",                # Classification Label
        ]
        self._frames = []
        


    def load_pcap(self, pcap):

        """
        This function takes in a pcap file saves it
        as a scapy PacketList.

        Args:
            pcap (str): OS location to a pcap file.
        """
        self._pcap = rdpcap(pcap)
        self._frames = []
    
    def _get_sessions(self, packet):

        """
        This function takes in packets and builds
        bi-directional flows between source and
        destinations.

        This is to be used in conjuction with a
        scapy PacketList object.

        Example:

        packet_capture = rdpcap(test.pcap)
        session_flows = packet_capture.sessions(_get_sessions)

        Args:
            packet (packet): A packet placeholder handled by scapy.

        Returns a dictionary with session information as the key
        and the corresponding bi-directional PacketList object

        Example Output:

            {
            "['192.168.86.21', '192.168.86.22', 60604, 8009, 'TCP']": <PacketList: TCP:6 UDP:0 ICMP:0 Other:0>, 
            "['192.168.86.21', '34.212.215.14', 443, 60832, 'TCP']": <PacketList: TCP:9 UDP:0 ICMP:0 Other:0>
            }

        """
        sess = "Other"
        if "Ether" in packet:
            if "IP" in packet:
                if "TCP" in packet:
                    sess = str(sorted(["TCP", packet["IP"].src, packet["TCP"].sport,
                                    packet["IP"].dst, packet["TCP"].dport], key=str))
                elif "UDP" in packet:
                    sess = str(sorted(["UDP", packet["IP"].src, packet["UDP"].sport,
                                    packet["IP"].dst, packet["UDP"].dport], key=str))
                elif "ICMP" in packet:
                    sess = str(sorted(["ICMP", packet["IP"].src, packet["IP"].dst,
                                    packet["ICMP"].code, packet["ICMP"].type, packet["ICMP"].id], key=str))
                else:
                    sess = str(sorted(["IP", packet["IP"].src, packet["IP"].dst,
                                    packet["IP"].proto], key=str))
            elif "ARP" in packet:
                sess = str(sorted(["ARP", packet["ARP"].psrc, packet["ARP"].pdst], key=str))
            else:
                sess = packet.sprintf("Ethernet type = %04xr,Ether.type%")
        return sess

    def build_dataframe(self, packet_list):

        """
        This function takes in a scapy PacketList object and 
        builds a pandas dataframe.

        Args:
            packet_list (PacketList): A scapy PacketList object.
        
        """
        ip_fields = [field.name for field in IP().fields_desc]
        tcp_fields = [field.name for field in TCP().fields_desc]
        udp_fields = [field.name for field in UDP().fields_desc]

        dataframe_fields = ip_fields + ['time'] + tcp_fields + ['size','payload','payload_raw','payload_hex']

        # Create blank DataFrame
        df = pd.DataFrame(columns=dataframe_fields)
        for packet in packet_list[IP]:
            # Field array for each row of DataFrame
            field_values = []
            # Add all IP fields to dataframe
            for field in ip_fields:
                if field == 'options':
                    # Retrieving number of options defined in IP Header
                    field_values.append(len(packet[IP].fields[field]))
                else:
                    field_values.append(packet[IP].fields[field])

            field_values.append(packet.time)

            layer_type = type(packet[IP].payload)
            for field in tcp_fields:
                try:
                    if field == 'options':
                        field_values.append(len(packet[layer_type].fields[field]))
                    else:
                        field_values.append(packet[layer_type].fields[field])
                except:
                    field_values.append(None)
            
            # Append payload
            field_values.append(len(packet))
            field_values.append(len(packet[layer_type].payload))
            field_values.append(packet[layer_type].payload.original)
            field_values.append(binascii.hexlify(packet[layer_type].payload.original))
            # Add row to DF
            df_append = pd.DataFrame([field_values], columns=dataframe_fields)
            df = pd.concat([df, df_append], axis=0)
            
        # Reset Index
        df = df.reset_index()
        # Drop old index column
        df = df.drop(columns="index")
        return df

    def build_sessions(self):
			  
        """
        This function returns dictionary of bi-directional
        flows.

        """
        return self._pcap.sessions(self._get_sessions)

    def get_src_ip(self, df):

        """
        This function should take in a pandas dataframe object
        that contains all the information for a single bi-directional
        flow. It will return the source IP address of the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        
        """
        return df["src"].unique().tolist()[0]

    def get_dst_ip(self, df):

        """
        This function should take in a pandas dataframe object
        that contains all the information for a single bi-directional
        flow. It will return the destination IP address of the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        
        """
        
        if df["src"].unique().shape[0] == 2:
            self.multicast_flag = 0
            return df["src"].unique().tolist()[1]
        else:
            self.multicast_flag = 1
            return df["dst"].unique().tolist()[0]
		
    def get_flow_duration(self, df):
        
        """
        This function returns the total time for the session flow.
        """

        if df.shape[0] == 1:
            return 1
        df["date_time"] = pd.to_datetime(df["time"], unit="s")
        idx = df.columns.get_loc("date_time")
        duration = (df.iloc[-1, idx] - df.iloc[0,idx]) / np.timedelta64(1, 's')
        return duration

		
    def get_total_len_forward_packets(self, df):
        
        """
        This function calculates the total length of all packets that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
			
        """
        
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return src_df["size"].sum()
		
    
    def get_total_len_backward_packets(self, df):
	
        """
        This function calculates the total length of all packets that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
			
        """

        if self.multicast_flag == 1:
            return 0
        
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        
        return src_df["size"].sum()
	
    def get_total_forward_packets(self, df):
    
        """
        This function calculates the total number of packets that
        originated from the source IP address

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        return  df.loc[df['src']==src].shape[0]

    
    def get_total_backward_packets(self, df):
    
        """
        This function calculates the total number of packets that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        return  df.loc[df['src']==src].shape[0]

    def get_min_forward_packet_size(self, df):
    
        """
        This function calculates the minimum payload size that
        originated from the source IP address
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  min(src_df["size"])

    def get_min_backward_packet_size(self, df):
    
        """
        This function calculates the minimum payload size that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        if self.multicast_flag == 1:
            return 0
        else:
            return  min(src_df["size"])

    def get_max_forward_packet_size(self, df):
    
        """
        This function calculates the maximum payload size that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  max(src_df["size"])

    def get_max_backward_packet_size(self, df):
    
        """
        This function calculates the maximum payload size that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        if self.multicast_flag == 1:
            return 0
        else:
            return  max(src_df["size"])

    def get_mean_forward_packet_size(self, df):
    
        """
        This function calculates the mean payload size that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].mean()

    def get_mean_backward_packet_size(self, df):
    
        """
        This function calculates the mean payload size that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].mean()
    
    def get_std_forward_packet_size(self, df):
    
        """
        This function calculates the standard deviation of payload sizes that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].std()

    def get_std_backward_packet_size(self, df):
    
        """
        This function calculates the standard deviaton of payload sizes that
        originated from the destination IP address
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].std()

    def get_iat_forward_total_time(self, df):
    
        """
        This function calculates the total inter arrival 
        time (iat) of packets from the source IP address.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["time"].diff().sum() 

    def get_iat_backward_total_time(self, df):
    
        """
        This function calculates the total inter arrival 
        time (iat) of packets from the destination IP address.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["time"].diff().sum() 

    def get_src_times(self, df):
    
        """
        This function returns the "time" Series object 
        from the passed in dataframe for the session
        source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["time"]

    def get_dst_times(self, df):
        
        """
        This function returns the "time" Series object 
        from the passed in dataframe for the session
        destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["time"]

    def get_iat_forward_min_times(self, df):
    
        """
        This function returns the minimum inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        if src_times.shape[0] > 1:
            return  min(src_times.diff().dropna()) 
        else:
            return src_times.tolist()[0]

    def get_iat_backwards_min_times(self, df):
        
        """
        This function returns the minimum inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        if self.multicast_flag == 1 or src_times.shape[0] == 1:
            return 0 # Test
        else:
            return  min(src_times.diff().dropna().tolist()) 

    def get_iat_forward_max_times(self, df):
    
        """
        This function returns the maximum inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        if src_times.shape[0] > 1:
            return  max(src_times.diff().dropna().tolist()) 
        else:
            return src_times.tolist()[0]

    def get_iat_backwards_max_times(self, df):
        
        """
        This function returns the maximum inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        return  max(src_times.diff().dropna()) 

    def get_iat_forward_mean_times(self, df):
        
        """
        This function returns the mean inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        return  src_times.diff().dropna().mean() 

    def get_iat_backwards_mean_times(self, df):
        
        """
        This function returns the mean inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        return  src_times.diff().dropna().mean() 

    def get_iat_forward_std_times(self, df):
    
        """
        This function returns the standard deviation for inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        return  src_times.diff().dropna().std() 

    def get_iat_backwards_std_times(self, df):
        
        """
        This function returns the standard deviation inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        return  src_times.diff().dropna().std() 

    def remove_duplicate_flags_col(self, df):
    
        """
        This function removes the first occurence
        of the 'flags' column due to multiple
        columns named 'flags'
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        column_numbers = [x for x in range(df.shape[1])]
        column_numbers.remove(5)
        return df.iloc[:, column_numbers]

    def decode_flags(self, df):
    
        """
        This function decodes the bitwise flag
        into a string.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            
        """
        
        return df["flags"].apply(lambda x: str(x))

    def count_flags(self, df, ip, flag):
        
        """
        This function counts the total number of
        flags from the specified origin.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            ip (String): A string representation of the IP address
            flag (String): The first letter of the flag to search.
        """
        
        df = df.loc[df["src"]==ip]
        df["flags"] = self.decode_flags(df).str.contains(flag)
        return df[df["flags"] == True].shape[0]

    def get_total_forward_push_flags(self, df):
    
        """
        This function calculates the total number of
        push flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        return self.count_flags(df, src, "P")

    def get_total_backward_push_flags(self, df):
        
        """
        This function calculates the total number of
        push flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_dst_ip(df)
        return self.count_flags(df, src, "P")

    def get_total_forward_urgent_flags(self, df):
    
        """
        This function calculates the total number of
        urgent flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        return self.count_flags(df, src, "U")

    def get_total_backward_urgent_flags(self, df):
        
        """
        This function calculates the total number of
        urgent flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_dst_ip(df)
        return self.count_flags(df, src, "U")

    def get_total_header_len_forward_packets(self, df):
    
        """
        This function calculates the total size
        of headers in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
            
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        return src_df["size"].sum() - self.get_total_len_forward_packets(df)

    def get_total_header_len_backward_packets(self, df):
        
        """
        This function calculates the total size
        of headers in the backward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        if self.multicast_flag == 1:
            return 0
        else:
            return src_df["size"].sum() - self.get_total_len_backward_packets(df)

    def get_forward_packets_per_second(self, df):
    
        """
        This function calculates number of packets
        per second in the forward direction.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if df.shape[0] > 1:
            return self.get_total_forward_packets(df) / self.get_flow_duration(df)
        else:
             return 1

    def get_backward_packets_per_second(self, df):
        
        """
        This function calculates number of packets
        per second in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        if df.shape[0] > 1:
            return self.get_total_backward_packets(df) / self.get_flow_duration(df) 
        else:
             return 1

    def get_flow_packets_per_second(self, df):
    
        """
        This function calculates number of packets
        per second in the flow.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if df.shape[0] > 1:
            return (self.get_total_backward_packets(df) + self.get_total_forward_packets(df)) / self.get_flow_duration(df)
        else:
            return 1

    def get_flow_bytes_per_second(self, df):
    
        """
        This function calculates number of bytes
        per second in the flow.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        return (self.get_total_len_forward_packets(df) + self.get_total_len_backward_packets(df)) / self.get_flow_duration(df)

    def get_min_flow_packet_size(self, df):
    
        """
        This function calculates the minimum payload size that
        originated from flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  min(df["size"])
        
    def get_max_flow_packet_size(self, df):
        
        """
        This function calculates the maximum payload size that
        originated from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  max(df["size"])

    def get_mean_flow_packet_size(self, df):
    
        """
        This function calculates the mean payload size that
        originated from flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  df["size"].mean()
    
    def get_std_flow_packet_size(self, df):

        """
        This function calculates the payloads tandard deviation size that
        originated from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """

        return  df["size"].std()

    def get_min_flow_iat(self, df):
    
        """
        This function calculates the min inter arival time
        from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if df.shape[0] > 1:
            return  min(df["time"].diff().dropna())
        else:
            return 0
    
    def get_max_flow_iat(self, df):
    
        """
        This function calculates the max inter arival time
        from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        if df.shape[0] > 1:
            return  max(df["time"].diff().dropna())
        else:
            return 0


    def get_mean_flow_iat(self, df):
    
        """
        This function calculates the mean inter arival time
        from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        #src_times = get_src_times(df)
        return df["time"].diff().dropna().mean()
    
    def get_std_flow_iat(self, df):
    
        """
        This function calculates the inter arival time
        standard deviation from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  df["time"].diff().dropna().std()

    def get_total_flow_push_flags(self, df):
    
        """
        This function calculates the total number
        of push flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "P") + self.count_flags(df, dst, "P")


    def get_total_flow_fin_flags(self, df):
        
        """
        This function calculates the total number
        of finish flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "F") + self.count_flags(df, dst, "F")

    def get_total_flow_syn_flags(self, df):
    
        """
        This function calculates the total number
        of syn flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "S") + self.count_flags(df, dst, "S")


    def get_total_flow_reset_flags(self, df):
        
        """
        This function calculates the total number
        of reset flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "R") + self.count_flags(df, dst, "R")

    def get_total_flow_ack_flags(self, df):
        
        """
        This function calculates the total number
        of ack flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "A") + self.count_flags(df, dst, "A")


    def get_total_flow_urg_flags(self, df):
        
        """
        This function calculates the total number
        of urgent flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "U") + self.count_flags(df, dst, "U")

    def get_total_flow_cwr_flags(self, df):
    
        """
        This function calculates the total number
        of cwr flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "C") + self.count_flags(df, dst, "C")


    def get_total_flow_ece_flags(self, df):
        
        """
        This function calculates the total number
        of ece flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "E") + self.count_flags(df, dst, "E")

    def get_average_burst_rate(self, df, window=100):
    
        """
        This is a helper function calculates the average burst rate
        based on the number of packets sent in the 
        burst window.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            window (Int): The number in milliseconds to calculate the burst rate
        """
        if self.multicast_flag == 1:
            return 0 

        a = pd.DataFrame()
        a["time"] = pd.to_datetime(df["time"], unit="s")
        a["count"] = 1
        a.set_index(["time"], inplace=True)
        a["rolling"] = a.rolling('100ms').sum()
        return a["rolling"].mean()

    def get_average_forward_bytes_per_burt(self, df, window=100):
    
        """
        This finds the average bytes per burst
        that originated from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            window (Int): The number in milliseconds to calculate the burst rate
        """
        
        if self.multicast_flag == 1:
            return 0
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        src_burst_rate = self.get_average_burst_rate(src_df)
        src_bytes = self.get_total_len_forward_packets(src_df)
        return src_bytes / src_burst_rate


    def get_average_backward_bytes_per_burt(self, df, window=100):
        
        """
        This finds the average bytes per burst
        that originated from the destination.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            window (Int): The number in milliseconds to calculate the burst rate
        """

        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        src_burst_rate = self.get_average_burst_rate(src_df)
        src_bytes = self.get_total_len_backward_packets(src_df)
        if self.multicast_flag == 1:
            return 0
        else:
            return src_bytes / src_burst_rate

    def get_upload_download_ratio(self, df):
    
        """
        This finds the upload to download ratio.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if self.multicast_flag == 1:
            return 1
        else:
            return self.get_total_len_forward_packets(df) / self.get_total_len_backward_packets(df)

    def get_avg_packet_size(self, df):
    
        """
        This finds the average packet size
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        return df["size"].mean()

    def get_avg_forward_segment_size(self, df):
    
        """
        This finds the average segment size in
        the forward direction.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        
        return src_df["payload"].mean()

    def get_avg_backward_segment_size(self, df):
        
        """
        This finds the average segment size in
        the forward direction.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        
        return src_df["payload"].mean()

    def get_avg_forward_burst_packets(self, df):
    
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df)

    def get_avg_backward_burst_packets(self, df):
        
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df)

    def get_avg_forward_in_total_burst(self, df):
    
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        if self.multicast_flag == 1:
            return 0

        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df) / self.get_average_burst_rate(df)

    def get_avg_backward_in_total_burst(self, df):
        
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        if self.multicast_flag == 1:
            return 0

        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df) / self.get_average_burst_rate(df)

    def get_src_port(self, df):
    
        """
        This finds the source port in the flow.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        df = df.iloc[0,]
        return df[["src", "sport", "dst", "dport"]].tolist()[1]

    def get_dst_port(self, df):
    
        """
        This finds the destination port in the flow.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        df = df.iloc[0,]
        return df[["src", "sport", "dst", "dport"]].tolist()[3]

    def build_index(self, df):

        """
        This buids the index to be used in the dataframe
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        dst_df = df[df["src"]==dst]
        src_port = src_df["sport"].unique()
        dst_port = dst_df["sport"].unique()
        
        if self.multicast_flag == 0:
            return ("{}:{}<->{}:{}").format(src,str(src_port[0]),dst,str(dst_port[0]))
        else:
            return ("{}:{}<->{}:{}").format(src,str(src_port[0]),dst,str(src_port[0]))

 
    def _build_feature_from_flow(self, flow):


        # print(("\nEntering {}").format(flow)) # Test

        if flow == "Other" or "Ethernet" in flow or "ARP" in flow: 
            pass
        else:
            flow = self.build_dataframe(self._sessions[flow])
            result = pd.DataFrame(columns=self.columns)
            result["flow"] = [self.build_index(flow)]
            result["src"] = [self.get_src_ip(flow)]
            result["src_port"] = [self.get_src_port(flow)]
            result["dst"] = [self.get_dst_ip(flow)]
            result["dst_port"] = [self.get_dst_port(flow)]
            result["feduration"] = [self.get_flow_duration(flow)]
            result["total_fpackets"] = [self.get_total_forward_packets(flow)]
            result["total_bpackets"] = [self.get_total_backward_packets(flow)]
            result["total_fpktl"] = [self.get_total_len_forward_packets(flow)]
            result["total_bpktl"] = [self.get_total_len_backward_packets(flow)]
            result["min_fpktl"] = [self.get_min_forward_packet_size(flow)]
            result["min_bpktl"] = [self.get_min_backward_packet_size(flow)]
            result["max_fpktl"] = [self.get_max_forward_packet_size(flow)]
            result["max_bpktl"] = [self.get_max_backward_packet_size(flow)]
            result["mean_fpktl"] = [self.get_mean_forward_packet_size(flow)]
            result["mean_bpktl"] = [self.get_mean_backward_packet_size(flow)]
            result["std_fpktl"] = [self.get_std_forward_packet_size(flow)]
            result["std_bpktl"] = [self.get_std_backward_packet_size(flow)]
            result["total_fiat"] = [self.get_iat_forward_total_time(flow)]
            result["total_biat"] = [self.get_iat_backward_total_time(flow)]
            result["min_fiat"] = [self.get_iat_forward_min_times(flow)]
            result["min_biat"] = [self.get_iat_backwards_min_times(flow)]
            result["max_fiat"] = [self.get_iat_forward_max_times(flow)]
            result["max_biat"] = [self.get_iat_forward_max_times(flow)]
            result["mean_fiat"] = [self.get_iat_forward_mean_times(flow)]
            result["mean_biat"] = [self.get_iat_backwards_mean_times(flow)]
            result["std_fiat"] = [self.get_iat_forward_std_times(flow)]
            result["std_biat"] = [self.get_iat_backwards_std_times(flow)]
            result["fpsh_cnt"] = [self.get_total_forward_push_flags(flow)]
            result["bpsh_cnt"] = [self.get_total_backward_push_flags(flow)]
            result["furg_cnt"] = [self.get_total_forward_urgent_flags(flow)]
            result["burg_cnt"] = [self.get_total_backward_urgent_flags(flow)]
            result["total_fhlen"] = [self.get_total_header_len_forward_packets(flow)]
            result["total_bhlen"] = [self.get_total_header_len_backward_packets(flow)]
            result["fPktsPerSecond"] = [self.get_forward_packets_per_second(flow)]
            result["bPktsPerSecond"] = [self.get_backward_packets_per_second(flow)]
            result["flowPktsPerSecond"] = [self.get_flow_packets_per_second(flow)]
            result["flowBytesPerSecond"] = [self.get_flow_bytes_per_second(flow)]
            result["min_flowpktl"] = [self.get_min_flow_packet_size(flow)]
            result["max_flowpktl"] = [self.get_max_flow_packet_size(flow)]
            result["mean_flowpktl"] = [self.get_mean_flow_packet_size(flow)]
            result["std_flowpktl"] = [self.get_std_flow_packet_size(flow)]
            result["min_flowiat"] = [self.get_min_flow_iat(flow)]
            result["max_flowiat"] = [self.get_max_flow_iat(flow)]
            result["mean_flowiat"] = [self.get_mean_flow_iat(flow)]
            result["std_flowiat"] = [self.get_std_flow_iat(flow)]
            result["flow_fin"] = [self.get_total_flow_fin_flags(flow)]
            result["flow_syn"] = [self.get_total_flow_syn_flags(flow)]
            result["flow_rst"] = [self.get_total_flow_reset_flags(flow)]
            result["flow_psh"] = [self.get_total_flow_push_flags(flow)]
            result["flow_ack"] = [self.get_total_flow_ack_flags(flow)]
            result["flow_urg"] = [self.get_total_flow_urg_flags(flow)]
            result["flow_cwr"] = [self.get_total_flow_cwr_flags(flow)]
            result["flow_ece"] = [self.get_total_flow_ece_flags(flow)]
            result["downUpRatio"] = [self.get_upload_download_ratio(flow)]
            result["avgPacketSize"] = [self.get_avg_packet_size(flow)]
            result["fAvgSegmentSize"] = [self.get_avg_forward_segment_size(flow)]
            result["fAvgBytesPerBulk"] = [self.get_average_forward_bytes_per_burt(flow)]
            result["fAvgPacketsPerBulk"] = [self.get_avg_forward_burst_packets(flow)]
            result["fAvgBulkRate"] = [self.get_avg_forward_in_total_burst(flow)]
            result["bAvgSegmentSize"] = [self.get_avg_backward_segment_size(flow)]
            result["bAvgBytesPerBulk"] = [self.get_average_backward_bytes_per_burt(flow)]
            result["bAvgPacketsPerBulk"] = [self.get_avg_backward_burst_packets(flow)]
            result["bAvgBulkRate"] = [self.get_avg_backward_in_total_burst(flow)]
            result["label"] = ["None"]
            #print(("\nAppending {}\n").format(result))
            return result
            #print(self._frames)


    def _build_sessions(self):
        return self.build_sessions()


    def build_feature_dataframe(self):        
        
        
        self._sessions = self.build_sessions()
        # print("\nBuilding Pool\n") # Test
        pool = Pool()


        self._frames = pool.map(self._build_feature_from_flow, self._sessions)
        # print(self._frames) # Test
        
        final = pd.concat(self._frames)
        final.set_index(["flow"], inplace=True)
        for column in final.columns:
            final[column] = final[column].replace(r'\s+', np.nan, regex=True)
            final[column] = final[column].fillna(0)

        return final


