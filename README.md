# DNSHunter

**DNSHunter** is a GUI-based network attack and analysis tool for educational and authorized testing purposes. It provides a set of features for network reconnaissance, MAC spoofing, ARP spoofing, and DNS sniffing, all through an intuitive graphical interface.

---

## Features

- **DNS Sniffer:**  
  Captures and displays DNS queries made by a selected target device on the network. You can include or exclude domains containing specific keywords.

- **MAC Spoofer:**  
  Allows you to spoof the MAC address of your network interface. You can set a specific MAC address, generate a random one, or restore the original MAC address.

- **Host Discovery:**  
  Scans the local network to discover connected devices. You can select a target device for the attack from the discovered hosts.

- **ARP Spoofer:**  
  Performs ARP spoofing to intercept or disrupt the target's network traffic. You can enable port forwarding to redirect the target's traffic for DNS sniffing, or disable it to cut off the target's network access.

---

## Screenshots

![Screenshot_DNSHunter](https://github.com/user-attachments/assets/fdd07946-057a-4cc5-8629-c274e61a0bb4)


---

## Requirements

- Python 3.7+
- Linux (tested on Debian-based distributions)
- Root privileges
- Dependencies:
  - `scapy`
  - `tkinter`
  - `ttk` (usually included with tkinter)
  - `iproute2` (for the `ip` command)
  - `iptables` (for port forwarding)
  - OUI file named `ouis` in the script directory (for MAC vendor lookup)

Install Python dependencies with:

```bash
pip install scapy
```

Install iptables

```bash
sudo apt install iptables
```

Install iproute2

```bash
sudo apt install iproute2
```

---

## Usage

1. **Run the script with root privileges:**
    ```bash
    sudo python3 spoofer13.py
    ```

2. **MAC Spoofer:**  
   Use the MAC Spoofer section to change your MAC address (set manually, randomize, or restore).

3. **Host Discovery:**  
   Scan your network and select a target device from the discovered hosts.

4. **ARP Spoofer:**  
   Start the ARP Spoofer to intercept or disrupt the target's network traffic. Enable or disable port forwarding as needed.

5. **DNS Sniffer:**  
   Capture and analyze DNS queries from the target device. You can filter domains by including or excluding specific keywords.

---

## GUI & Display Notes

> **Important:**  
> The graphical interface is optimized for displays with a resolution of 1080p (1920x1080) or higher.  
> For optimal appearance and usability, ensure that your operating system's display scaling (DPI scaling or interface zoom) is set to 100%.  
> Increasing the system-wide interface scaling may cause layout or rendering issues.

---

## Disclaimer

This tool is intended **for educational and authorized testing purposes only**.  
**Do not use it for malicious activities or unauthorized access to networks or devices.**  
The author assumes no responsibility for any misuse or damage caused by this tool.

## Author

- deeb
  
## Acknowledgements

- [Scapy](https://scapy.net/)
- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)
