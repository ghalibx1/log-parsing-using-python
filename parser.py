import argparse
import ipaddress
import re

log_file_path = '<PATH>/access.log'  # Path to log file

def extract_logs_for_ipcidr(log_file_path, user_input):
    # Regular expression pattern to match an IP address
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Converting the IP-CIDR range to an ipaddress network object
    network = ipaddress.ip_network(user_input)

    # Listing to store matching logs
    matching_lines = []

    # Openning the log file and parseing each line
    with open(log_file_path, 'r') as file:
        for line in file:
            # Finding all IP addresses in the line
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip_str = ip_match.group()
                ip_obj = ipaddress.ip_address(ip_str)
                # Checking if the IP address falls within the specified CIDR range
                if ip_obj in network:
                    matching_lines.append(line.strip())

    return matching_lines

# Setting up argument parser
parser = argparse.ArgumentParser(description="Input argument IP")
parser.add_argument("--ip", type=str, help="Input argument IP", required=True)
args = parser.parse_args()

try:
    ip_network = ipaddress.ip_network(args.ip, strict=False)
    matching_log_lines = extract_logs_for_ipcidr(log_file_path, args.ip)
    
    # Displaying the filtered logs
    print("Logs matching the specified IP-CIDR range:")
    for line in matching_log_lines:
        print(line)
        
except ValueError:
    print(f"The input '{args.ip}' is NOT a valid CIDR notation.")
