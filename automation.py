import paramiko
import argparse
import time
import subprocess
import threading
from datetime import datetime

def print_colored_log(message, color_code):
    """
    Prints messages in color with a timestamp.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\033[{color_code}m[{timestamp}] {message}\033[0m")

def ssh_command(host, key_path, command):
    """
    SSH into a given host and run a command. Handles timeout and retries.
    """
    retries = 3
    for attempt in range(retries):
        try:
            # Establish SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username='ubuntu', key_filename=key_path)
            print_colored_log(f"SSH connection to {host} successful.", 32)  # Green

            # Source the profile and manua setting of Zeek environment variables 
          
            command_to_set_env = """
            source ~/.bashrc && 
            export PATH=$PATH:/opt/zeek/bin && 
            export ZEKK_INSTALL_PATH=/opt/zeek && 
            export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/zeek/lib
            """

            environment setup command
            ssh.exec_command(command_to_set_env)

            # Run commands
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()

            # Close SSH connection
            ssh.close()

            if error:
                print_colored_log(f"Error on {host}: {error}", 31)  # Red
            return output
        
        except Exception as e:
            print_colored_log(f"Attempt {attempt + 1} failed to connect to {host}: {e}", 33)  # Yellow
            if attempt < retries - 1:
                time.sleep(5)  # Retry after 5 seconds
            else:
                raise Exception(f"Failed to connect to {host} after {retries} attempts")

def run_zeek_manager_commands(key_path):
    """
    Run Zeek control commands on the manager.
    """
    manager_host = "ec2-13-210-72-72.ap-southeast-2.compute.amazonaws.com"
    commands = [
        "cd /opt/zeek/bin && ./zeekctl stop",
        "cd /opt/zeek/bin && ./zeekctl start",
        "cd /opt/zeek/bin && ./zeekctl status"
    ]
    
    for command in commands:
        print_colored_log(f"Running on Zeek Manager: {command}", 36)  # Cyan
        output = ssh_command(manager_host, key_path, command)
        print_colored_log(f"Output from Zeek Manager: {output}", 34)  # Blue

def run_zeek_worker_commands(worker_host, key_path, pcap_file):
    """
    Run tcpreplay on Zeek worker instances.
    """
    command = f"sudo tcpreplay --intf1=enX0 --mbps=1000 {pcap_file}"  # Increased speed to 1000 Mbps
    print_colored_log(f"Running on Zeek Worker: {command}", 36)  # Cyan
    output = ssh_command(worker_host, key_path, command)
    print_colored_log(f"Output from Zeek Worker: {output}", 34)  # Blue

def run_log_verification(manager_host, key_path):
    """
    Run the log verification script (zeek_log_compare.py) on the manager instance.
    """
    print_colored_log("Running log verification script on Zeek Manager...", 36)  # Cyan
    log_verification_command = "source ~/.bashrc && export PATH=$PATH:/opt/zeek/bin && python3 ssl_log_compare.py bigFlows.pcap smallFlows.pcap "  # Ensuring correct environment variables
    output = ssh_command(manager_host, key_path, log_verification_command)
    print_colored_log(f"Log verification output from Zeek Manager:\n{output}", 34)  # Blue

def run_worker_tcpreplay_parallel(worker_hosts, pcap_files, key_path):
    """
    Run tcpreplay on Zeek workers in parallel.
    """
    threads = []
    for worker_host, pcap_file in zip(worker_hosts, pcap_files):
        thread = threading.Thread(target=run_zeek_worker_commands, args=(worker_host, key_path, pcap_file))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish before continuing
    for thread in threads:
        thread.join()

def main():
    parser = argparse.ArgumentParser(description='Automate Zeek setup and traffic replay')
    parser.add_argument('--key', required=True, help='Path to the SSH private key (e.g., zeektest.pem)')
    
    args = parser.parse_args()

    # Step 1: Run Zeek manager commands
    run_zeek_manager_commands(args.key)
    
    # Step 2: Run tcpreplay on Zeek workers in parallel
    worker_pcap_files = [
        'smallFlows.pcap',  # worker 1 pcap
        'bigFlows.pcap'   # worker 2 pcap
    ]
    
    worker_hosts = [
        "ec2-13-210-189-55.ap-southeast-2.compute.amazonaws.com",
        "ec2-54-206-61-204.ap-southeast-2.compute.amazonaws.com"
    ]
    
    # Run tcpreplay on workers in parallel, wait for completion
    run_worker_tcpreplay_parallel(worker_hosts, worker_pcap_files, args.key)

    # Step 3: Prompt user to continue with log verification
    user_input = input("Do you want to run the log verification script now? (yes/no): ").strip().lower()
    
    if user_input == "yes":
        manager_host = "ec2-13-210-72-72.ap-southeast-2.compute.amazonaws.com"
        run_log_verification(manager_host, args.key)
    else:
        print_colored_log("Log verification was skipped.", 33)  # Yellow

if __name__ == '__main__':
    main()
