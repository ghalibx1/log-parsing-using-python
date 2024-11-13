import argparse
import ipaddress
import re
from collections import Counter
from datetime import datetime

log_file_path = '<PATH>/access.log'  # Path to log file
time_stamp_pattern = <regex>


def ip_rpm(log_file_path, user_input_rpm):
  with open(log_file_path, 'r') as file:
    for line in file:
      timestamp_str = #have to split the date and time before converting them into data-time obj i.e."%d/%b/%Y:%H:%M:%S" 
      timestamp_obj=timestamps.append()
      
  return 


def topips(log_file_path, user_input_topip):
  with open(log_file_path, 'r') as file:
    for 
    ip_counts = Counter(ips)
  
top_ip_counts = ip_counts.most_common(user_input_topip)
return top_ip_counts
    
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
              # converting into to an ip_address object.
                ip_obj = ipaddress.ip_address(ip_str)
                # Checking if the IP address falls within the specified CIDR range
                if ip_obj in network:
                    matching_lines.append(line.strip())

    return matching_lines

# Setting up argument parser
parser = argparse.ArgumentParser(description="Input argument IP")
parser.add_argument("--ip", type=str, help="Input argument IP", required=True)
args = parser.parse_args()

# Top IPs request
parser = argparse.ArgumentParser(description="Input argument TOP IPs")
parser.add_argument("--top_ips", type=str, help="Input argument TOP IPs", required=True)
args = parser.parse_args()

# Request Per Minute Calculation
parser = argparse.ArgumentParser(description="Input argument rpm")
parser.add_argument("--rpm", type=str, help="Input argument rpm", required=True)
args = parser.parse_args()

# Request Per Minute Calculation with Time Range
parser = argparse.ArgumentParser(description="Input argument rpm with timerange")
parser.add_argument("--start-time", type=str, help="Input argument Start Time", required=True)
parser.add_argument("--end-time", type=str, help="Input argument End Time", required=True)
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

else:
  top_ips_f=topips(log_file_path, args.top_ips)
  
  for IP, count in top_ips_f:
    print("IP Address: " ,IP, "Count: ",count)

#case 4
  rpm=ip_rpm(log_file_path, args.rpm)
# for loop to print the rpm

#case 5

#case 6

