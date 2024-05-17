import tkinter as tk
from tkinter import ttk, Toplevel, Label, Button
from scapy.all import sniff
from scapy.layers.inet import TCP, UDP, IP, ICMP
import threading
import queue
import matplotlib.pyplot as plt

blocked_ips = set()

traffic_volume = {}

notification_queue = queue.Queue()

stop_sniffing_event = threading.Event()

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        packet_info = {
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': protocol
        }

        update_traffic_volume(src_ip)
        update_traffic_volume(dst_ip)

        insert_packet(packet_info)

        if is_suspicious(packet_info):
            notify_user(packet_info)

        update_graph()

def insert_packet(packet_info):
    protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(packet_info['Protocol'], 'Other')
    tree.insert("", "end", values=(packet_info['Source IP'], packet_info['Destination IP'], protocol_name))

def is_suspicious(packet_info):
    src_ip = packet_info['Source IP']
    dst_ip = packet_info['Destination IP']
    protocol = packet_info['Protocol']

    suspicious_protocols = [17, 1]  # 17 is the protocol number for UDP, 1 is for ICMP
    if protocol in suspicious_protocols:
        return True

    suspicious_ips = ['10.0.0.1', '192.168.1.1']
    if src_ip in suspicious_ips or dst_ip in suspicious_ips:
        return True

    if traffic_volume.get(src_ip, 0) > 10 or traffic_volume.get(dst_ip, 0) > 10:
        return True

    return False






