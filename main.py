import threading
from scapy.all import ARP, Ether, srp


def send_arp_request(thread_num, target_ips, network_interface, result, no_response_ranges):
    start_ip = target_ips[0]
    end_ip = target_ips[-1]
    print(f"Thread {thread_num}: Sending ARP requests to devices {start_ip} through {end_ip}...")

    arp = ARP(pdst=target_ips)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    response, _ = srp(packet, timeout=3, iface=network_interface, verbose=False)

    if response:
        print(f"Thread {thread_num}: Received ARP responses from {len(response)} devices:")
        for sent, received in response:
            print(f"  - IP Address: {received.psrc}, MAC Address: {received.hwsrc}")
            result.append({'ip': received.psrc, 'mac': received.hwsrc})
    else:
        no_response_ranges.append((start_ip, end_ip))


def main():
    target_cidr = "192.168.1.0/24"  # Replace
    network_interface = "Wi-Fi"  # Replace
    num_threads = 5

    target_ips = [f"192.168.1.{host}" for host in range(1, 255)]
    chunk_size = len(target_ips) // num_threads

    threads = []
    result = []
    no_response_ranges = []

    print(f"Scanning {target_cidr} using {num_threads} threads...\n")

    for i in range(num_threads):
        start = i * chunk_size
        end = start + chunk_size if i < num_threads - 1 else len(target_ips)
        chunk = target_ips[start:end]

        thread = threading.Thread(target=send_arp_request, args=(i + 1, chunk, network_interface, result, no_response_ranges))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("\nDevices that did not respond:")
    for start_ip, end_ip in no_response_ranges:
        print(f"  - IP Range: {start_ip} through {end_ip}")

    print("\nScan complete. Discovered devices:")
    for device in result:
        print(f"IP Address: {device['ip']}, MAC Address: {device['mac']}")


if __name__ == "__main__":
    main()
