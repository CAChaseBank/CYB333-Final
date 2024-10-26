#Caleb Chase
#National University
#CYB333 Final Project
#Oct. 25, 2024

import os
import tkinter as tk
from tkinter import filedialog
from scapy.all import rdpcap, IP

#Select the pcap file for analysis
def select_pcap_file():
    root = tk.Tk()
    root.withdraw()

    pcap_file = filedialog.askopenfilename(
        title="Select a PCAP file",
        filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
    )

    return pcap_file

#Reads and imports packet info
def extract_ips_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    ip_addresses = set()
    traffic_counts = {}
    connection_counts = {}

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            #Add the IPs
            ip_addresses.add(src_ip)
            ip_addresses.add(dst_ip)

            #Count the source abd destination traffic
            traffic_counts[src_ip] = traffic_counts.get(src_ip, 0) + 1
            traffic_counts[dst_ip] = traffic_counts.get(dst_ip, 0) + 1
            
            #Count unique connections
            connection_key = (src_ip, dst_ip)
            if connection_key not in connection_counts:
                connection_counts[connection_key] = 1

    return ip_addresses, traffic_counts, connection_counts

#Choose the directory output
def select_output_directory():
    root = tk.Tk()
    root.withdraw()

    directory = filedialog.askdirectory(
        title="Select the directory to save the analysis folder"
    )

    return directory

def save_ips_to_file(ip_addresses, output_directory, pcap_filename, traffic_counts, connection_counts):
    #Create the folder name
    folder_name = os.path.splitext(os.path.basename(pcap_filename))[0]
    analysis_folder = os.path.join(output_directory, folder_name)
    
    #Make the directory
    os.makedirs(analysis_folder, exist_ok=True)

    output_file = os.path.join(analysis_folder, "All the IPs.txt")
    top_ips_file = os.path.join(analysis_folder, "Top 10 Connections.txt")
    least_ips_file = os.path.join(analysis_folder, "Least 10 Connections.txt")
    single_ip_file = os.path.join(analysis_folder, "Single Occurrence IPs.txt")
    master_report_file = os.path.join(analysis_folder, "Master Report.txt")
    
    #Save all IPs
    with open(output_file, "w") as f:
        for ip in ip_addresses:
            f.write(f"{ip}\n")

    #Save top 10 connections to file
    top_connections = sorted(connection_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    with open(top_ips_file, "w") as f:
        f.write("SRC IP --> DST IP\n")
        f.write("-------------------\n")
        for (src_ip, dst_ip), _ in top_connections:
            f.write(f"{src_ip} --> {dst_ip}\n")

    #Save least 10 connections to file
    least_connections = sorted(connection_counts.items(), key=lambda item: item[1])[:10]
    with open(least_ips_file, "w") as f:
        f.write("SRC IP --> DST IP\n")
        f.write("-------------------\n")
        for (src_ip, dst_ip), _ in least_connections:
            f.write(f"{src_ip} --> {dst_ip}\n")

    #Save IPs that only appear once
    single_occurrence_ips = [ip for ip, count in traffic_counts.items() if count == 1]
    with open(single_ip_file, "w") as f:
        for ip in single_occurrence_ips:
            f.write(f"{ip}\n")

    #Create the master report
    with open(master_report_file, "w") as f:
        f.write("Master Report\n")
        f.write("==============\n\n")
        
        f.write("All Unique IPs:\n")
        for ip in ip_addresses:
            f.write(f"{ip}\n")
        f.write("\n")

        f.write("Top 10 Connections:\n")
        for (src_ip, dst_ip), _ in top_connections:
            f.write(f"{src_ip} --> {dst_ip}\n")
        f.write("\n")

        f.write("Least 10 Connections:\n")
        for (src_ip, dst_ip), _ in least_connections:
            f.write(f"{src_ip} --> {dst_ip}\n")
        f.write("\n")

        f.write("IPs that appeared only once:\n")
        for ip in single_occurrence_ips:
            f.write(f"{ip}\n")

    return output_file, top_ips_file, least_ips_file, single_ip_file, master_report_file

#Prints confirmation
selected_file = select_pcap_file()
if selected_file:
    ip_addresses, traffic_counts, connection_counts = extract_ips_from_pcap(selected_file)
    output_directory = select_output_directory()
    if output_directory:
        output_file, top_ips_file, least_ips_file, single_ip_file, master_report_file = save_ips_to_file(ip_addresses, output_directory, selected_file, traffic_counts, connection_counts)
        print(f"Extracted {len(ip_addresses)} unique IP addresses to {output_file}.")
        print(f"Top 10 Connections saved to {top_ips_file}.")
        print(f"Least 10 Connections saved to {least_ips_file}.")
        print(f"IPs that appeared only once saved to {single_ip_file}.")
        print(f"Master report saved to {master_report_file}.")
    else:
        print("No output directory selected.")
else:
    print("No PCAP file selected.")
