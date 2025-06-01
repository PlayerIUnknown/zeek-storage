icacls zeektest.pem /inheritance:r
icacls zeektest.pem /grant:r "%USERNAME%:R"

---

# **Complete Zeek Cluster Setup Summary**

---

## 1. **Create EC2 Instances and Note IPs**

* Created two AWS EC2 instances in the same VPC:

  * **Manager Node:** 172.31.47.210 (private IP), with public IP assigned.
  * **Worker Node:** 172.31.37.40 (private IP), with public IP assigned.

* Both instances use Ubuntu.

---

## 2. **Install Zeek on Both Manager and Worker**

* Installed Zeek under `/opt/zeek` on **both** instances.
* Ensured identical Zeek versions on manager and worker.

---

## 3. **Set Up Passwordless SSH for Zeek Cluster Communication**

* ZeekControl (on manager) uses SSH to communicate with worker nodes for deployment and control.
* Passwordless SSH lets this happen automatically without manual password input.

### Steps:

**On Manager (172.31.47.210):**

* Generate SSH keypair as root or `ubuntu` user running Zeek:

  ```bash
  ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
  ```

* Copy the **public key** to the worker node’s authorized keys (as `ubuntu`):

  ```bash
  ssh-copy-id -i ~/.ssh/id_rsa.pub ubuntu@172.31.37.40
  ```

* Confirm passwordless login:

  ```bash
  ssh ubuntu@172.31.37.40
  ```

**Note:** You must use the same user (typically `ubuntu`) for ZeekControl SSH access on both machines.

---

## 4. **Set Permissions for Zeek Installation and Spool Directories**

### Issue

* Zeek needs to write logs, state files, and deploy scripts in `/opt/zeek/spool` and `/opt/zeek/logs`.
* By default, `/opt/zeek` may be owned by `root` and inaccessible to `ubuntu`.

### Fix

On **both manager and worker**:

```bash
sudo chown -R ubuntu:ubuntu /opt/zeek
sudo chmod -R 770 /opt/zeek
```

Make sure `ubuntu` user running ZeekControl and Zeek daemon has read/write/execute permissions.

---

## 5. **Configure Zeek Cluster `node.cfg`**

On **manager** (default location `/opt/zeek/etc/node.cfg`):

```ini
[manager]
type=manager
host=172.31.47.210

[proxy-1]
type=proxy
host=172.31.47.210

[worker-1]
type=worker
host=172.31.37.40
interface=af_packet::enX0   
lb_procs=1
lb_method=custom
```

* **proxy-1** is required for traffic load balancing and cluster communication.
* Ensure the interface specified exists on the worker.

---

## 6. **Grant Zeek Binary Network Capabilities (Worker Node)**

To capture packets on interfaces without running Zeek as root, run on **worker**:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek
```

---

## 7. **Verify Network Interface Name on Worker**

On **worker**:

```bash
ip link show
```

Confirm the interface name (e.g., `enX0`). Use the correct name in `node.cfg`.

---

## 8. **Adjust AWS Security Groups [Very Important] **

Ensure inbound and outbound rules allow required ports between manager and worker private IPs:

* TCP 27761 (cluster control)
* TCP 47760–47779 (Broker communication)

Also, allow SSH (port 22) for your user.

---

## 9. **Deploy and Start Zeek Cluster**

On **manager**:

```bash
cd /opt/zeek/bin
./zeekctl deploy
./zeekctl start
```

Check status:

```bash
./zeekctl status
```

---

## 10. **Verify Logs Directory on Manager**

```bash
sudo mkdir -p /opt/zeek/spool/logs/current
sudo chown -R ubuntu:ubuntu /opt/zeek/spool/logs
sudo chmod -R 770 /opt/zeek/spool/logs
```

```bash
sudo chown -R ubuntu:ubuntu /opt/zeek/logs
sudo chmod -R 770 /opt/zeek/logs
```
* Logs from workers should be forwarded here.

---

## 11. **Test Traffic Capture and Log Generation**

* On **worker**, generate network traffic:

```bash
ping -c 5 8.8.8.8
curl http://example.com
```

* On **manager**, check logs:

```bash
tail -f /opt/zeek/logs/current/conn.log
```

---
