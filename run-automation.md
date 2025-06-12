# Zeek Automation Script README

This script automates the setup and traffic replay on Zeek instances using SSH and `tcpreplay`. It allows for parallel traffic replay on two Zeek worker instances and manual control of the log verification step.

### Prerequisites

1. **Download the required files**:

   * **`zeektest.pem`** (SSH private key) and **`automation.py`** script locally.
   * The script is configured to work with the following **PCAP files**:

     * [bigFlows.pcap](https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap)
     * [smallFlows.pcap](https://s3.amazonaws.com/tcpreplay-pcap-files/smallFlows.pcap)

  * The pcap files are present on the workers and the manager instances already!
2. **Install Dependencies**:

   ```bash
   pip install paramiko
   ```

3. **Set SSH Key Permissions**:
   Before using the SSH key, ensure it has the correct permissions:

   ```bash
   chmod 400 zeektest.pem
   ```

### Script Flow

1. The script connects to **Zeek Manager** and **Zeek Worker** instances using SSH.
2. It runs **`tcpreplay`** on both worker instances in parallel, transmitting traffic from configured **PCAP files**.
3. After the traffic replay completes, the script prompts you to run the **log verification script**.
4. **Log verification** runs only if you answer "yes" to the prompt.


### How to Run

1. **Download and configure the files**:

   * Download `zeektest.pem` and the **`automation.py`** script locally.
   * Ensure the correct **PCAP files** are configured.

2. **Run the Script**:

   ```bash
   python automation.py --key /path/to/zeektest.pem
   ```

To Do: **Shutdown Instances**:

   * After completing the traffic replay and log verification, the script will automatically **shut down** the instances.



https://github.com/user-attachments/assets/191d5e7f-4b51-4f7c-9ee6-4bcc054fee0c


