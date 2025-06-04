import os
import subprocess
import pandas as pd

# === CONFIGURATION ===
PCAP_PATH = "/root/smallFlows.pcap"
OFFLINE_LOG_DIR = "/tmp/zeek_offline_logs"
CLUSTER_LOG_DIR = "/opt/zeek/logs/current"
LOG_FILES = ["conn.log", "dns.log", "http.log", "ssl.log"]

# === Fields to Compare Per Log ===
KEY_FIELDS = {
    "conn.log": ["id.orig_h", "id.resp_h", "proto", "service", "conn_state"],
    "dns.log": ["query", "qtype_name", "rcode_name", "answers"],
    "http.log": ["host", "uri", "method", "status_code", "user_agent"],
    "ssl.log": ["version", "cipher", "server_name", "validation_status"]
}

def run_zeek_offline():
    print(f"📦 Running Zeek offline on {PCAP_PATH}...")

    os.makedirs(OFFLINE_LOG_DIR, exist_ok=True)
    for f in os.listdir(OFFLINE_LOG_DIR):
        os.remove(os.path.join(OFFLINE_LOG_DIR, f))

    cmd = f"cd {OFFLINE_LOG_DIR} && zeek -C -r {PCAP_PATH}"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        print("❌ Zeek failed:\n", result.stderr.decode())
        exit(1)
    else:
        print("✅ Zeek log generation complete.")

def read_zeek_log(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()

        header_line = next(i for i, line in enumerate(lines) if line.startswith("#fields"))
        columns = lines[header_line].strip().split('\t')[1:]  # remove '#fields'

        df = pd.read_csv(filepath, sep='\t', comment='#', names=columns, header=None, skiprows=header_line+1, engine='python')
        return df
    except Exception as e:
        print(f"⚠️ Failed to read {filepath}: {e}")
        return None

def compare_logs(cluster_dir, offline_dir, log_file):
    print(f"\n🔍 Comparing {log_file}")
    cluster_path = os.path.join(cluster_dir, log_file)
    offline_path = os.path.join(offline_dir, log_file)

    if not os.path.exists(cluster_path) or not os.path.exists(offline_path):
        print(f"⚠️ Missing {log_file} in one or both directories.")
        return

    df_cluster = read_zeek_log(cluster_path)
    df_offline = read_zeek_log(offline_path)
    if df_cluster is None or df_offline is None:
        return

    fields = KEY_FIELDS.get(log_file, [])
    missing = [f for f in fields if f not in df_cluster.columns or f not in df_offline.columns]
    if missing:
        print(f"⚠️ Skipping {log_file}: missing fields {missing}")
        return

    df_cluster = df_cluster[fields].dropna(how='all').drop_duplicates().sort_values(by=fields).reset_index(drop=True)
    df_offline = df_offline[fields].dropna(how='all').drop_duplicates().sort_values(by=fields).reset_index(drop=True)

    set_cluster = set(map(tuple, df_cluster.to_numpy()))
    set_offline = set(map(tuple, df_offline.to_numpy()))

    only_cluster = set_cluster - set_offline
    only_offline = set_offline - set_cluster

    print(f"  ✅ Cluster filtered rows: {len(df_cluster)}")
    print(f"  ✅ Offline filtered rows: {len(df_offline)}")
    print(f"  ⚠️  Rows only in cluster: {len(only_cluster)}")
    print(f"  ⚠️  Rows only in offline: {len(only_offline)}")

    if only_cluster:
        print("  🔸 Example only in cluster:")
        print(list(only_cluster)[0])
    if only_offline:
        print("  🔹 Example only in offline:")
        print(list(only_offline)[0])

def main():
    run_zeek_offline()
    for log_file in LOG_FILES:
        compare_logs(CLUSTER_LOG_DIR, OFFLINE_LOG_DIR, log_file)

if __name__ == "__main__":
    main()
