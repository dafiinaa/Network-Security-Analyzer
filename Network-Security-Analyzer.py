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

        if is_suspicious(packet_info):
            notify_user(packet_info)
        else:
            insert_packet(packet_info)


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



def update_traffic_volume(ip):
    if ip in traffic_volume:
        traffic_volume[ip] += 1
    else:
        traffic_volume[ip] = 1

def notify_user(packet_info):
    notification_queue.put(packet_info)
    show_next_notification()

def show_next_notification():
    if not notification_queue.empty() and not hasattr(root, 'notification_window'):
        packet_info = notification_queue.get()
        notification_window(packet_info)

def notification_window(packet_info):
    def deny_packet():
        print(f"Denied access from {packet_info['Source IP']} to {packet_info['Destination IP']}")
        blocked_ips.add(packet_info['Source IP'])
        blocked_ips.add(packet_info['Destination IP'])
        window.destroy()
        delattr(root, 'notification_window')
        show_next_notification()

    def allow_packet():
        print("Packet allowed")
        insert_packet(packet_info)
        window.destroy()
        delattr(root, 'notification_window')
        show_next_notification()

    window = Toplevel(root)
    window.title("Suspicious Packet Detected")
    root.notification_window = window

    protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(packet_info['Protocol'], 'Other')
    message = f"Suspicious packet detected:\n\nSource IP: {packet_info['Source IP']}\nDestination IP: {packet_info['Destination IP']}\nProtocol: {protocol_name}\n\nDo you want to deny this packet?"
    Label(window, text=message, wraplength=400, justify="left").pack(pady=10)

    button_frame = ttk.Frame(window)
    button_frame.pack(pady=10)

    deny_button = Button(button_frame, text="Deny Packet", command=deny_packet)
    deny_button.grid(row=0, column=0, padx=5)

    allow_button = Button(button_frame, text="Allow", command=allow_packet)
    allow_button.grid(row=0, column=1, padx=5)


def start_sniffing():
    stop_sniffing_event.clear()
    sniff(prn=analyze_packet, stop_filter=lambda p: stop_sniffing_event.is_set(), store=0)

def stop_sniffing():
    stop_sniffing_event.set()

def run_sniffing():
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

def update_graph():
    ips = list(traffic_volume.keys())
    volumes = list(traffic_volume.values())
    plt.bar(ips, volumes)
    plt.xlabel('IP Address')
    plt.ylabel('Traffic Volume')
    plt.title('Traffic Volume per IP Address')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

root = tk.Tk()
root.title("Network Security Analyzer")

tree = ttk.Treeview(root, columns=('Source IP', 'Destination IP', 'Protocol'), show='headings')
tree.heading('Source IP', text='Source IP')
tree.heading('Destination IP', text='Destination IP')
tree.heading('Protocol', text='Protocol')

tree.pack(fill=tk.BOTH, expand=True)

start_button = tk.Button(root, text="Start Sniffing", command=run_sniffing)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(pady=5)

root.mainloop()





