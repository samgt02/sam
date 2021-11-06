import nmap

import re

# Regular Expression Pattern to recognise IPv4 addresses.
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialising the port numbers, will be using the variables later on.
port_min = 0
port_max = 65535

open_ports = []
nm = nmap.PortScanner()
# Ask user to input the ip address they want to scan.
while True:
    ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
    if ip_add_pattern.search(ip_add_entered):
        print(f"{ip_add_entered} is a valid ip address")
        break

while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning 
    # all the ports is not advised.
    print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break


# We're looping over all of the ports in the specified range.
for port in range(port_min, port_max + 1):
    try:
        
        result = nm.scan(ip_add_entered, str(port))
        # Uncomment following line and look at dictionary
        # print(result)
        # We extract the port status from the returned object
        port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
        
        if port_status=='open':
           print(f"Port {port} is {port_status}")
    except:
        # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
        print(f"Cannot scan port {port}.")

print("Print the hostname")
print(nm[ip_add_entered].hostname())

print("Print the status of the IP")
print(nm[ip_add_entered].state())

print("print all the protocol")
print(nm[ip_add_entered].all_protocols())

print("Print the keys")
print(nm[ip_add_entered]['tcp'].keys())

print("Testing the scan info")
print(nm.scaninfo())