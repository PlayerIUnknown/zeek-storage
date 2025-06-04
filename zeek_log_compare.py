import os
import subprocess
import pandas as pd

# === CONFIGURATION ===
PCAP_PATH = "/root/smallFlows.pcap"  # Update path if needed
OFFLINE_LOG_DIR = "/tmp/zeek_offline_logs"
CLUSTER_LOG_DIR = "/opt/zeek/logs/current"
LOG_FILES = ["conn.log", "dns.log", "http.log", "ssl.log"]

def run_zeek_offline():
    print(f"📦 Running Zeek offline on {PCAP_PATH}...")

    os.makedirs(OFFLINE_LOG_DIR, exist_ok=True)
    for file in os.listdir(OFFLINE_LOG_DIR):
        os.remove(os.path.join(OFFLINE_LOG_DIR, file))

    # Run Zeek inside the offline log directory
    cmd = f"cd {OFFLINE_LOG_DIR} && zeek -C -r {PCAP_PATH}"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        print("❌ Zeek failed:\n", result.stderr.decode())
        exit(1)
    else:
        print("✅ Zeek log generation complete.")

def read_log(file_path):
    try:
        return pd.read_csv(file_path, sep='\t', comment='#', low_memory=False)
    except Exception as e:
        print(f"⚠️ Error reading {file_path}: {e}")
        return None

def compare_logs(cluster_dir, offline_dir, log_file):
    cluster_log = os.path.join(cluster_dir, log_file)
    offline_log = os.path.join(offline_dir, log_file)

    if not os.path.exists(cluster_log) or not os.path.exists(offline_log):
        print(f"⚠️ Missing {log_file} in one of the directories.")
        return

    df_cluster = read_log(cluster_log)
    df_offline = read_log(offline_log)

    if df_cluster is None or df_offline is None:
        return

    # Define key fields for comparison per log type
    key_fields = {
        "conn.log": ["id.orig_h", "id.resp_h", "proto", "service", "conn_state"],
        "dns.log": ["query", "qtype_name", "rcode_name", "answers"],
        "http.log": ["host", "uri", "method", "status_code", "user_agent"],
        "ssl.log": ["version", "cipher", "server_name", "validation_status"]
    }

    expected_fields = key_fields.get(log_file, [])
    available_fields = list(set(expected_fields) & set(df_cluster.columns) & set(df_offline.columns))

    if not available_fields:
        print(f"\n⚠️ Skipping {log_file}: No matching fields to compare.")
        print(f"🔍 Cluster columns: {df_cluster.columns.tolist()}")
        print(f"🔍 Offline columns: {df_offline.columns.tolist()}")
        return

    df_cluster_trim = df_cluster[available_fields].dropna(how='all').drop_duplicates().sort_values(by=available_fields).reset_index(drop=True)
    df_offline_trim = df_offline[available_fields].dropna(how='all').drop_duplicates().sort_values(by=available_fields).reset_index(drop=True)

    print(f"\n🔍 Comparing {log_file}")
    print(f"  Cluster rows (filtered): {len(df_cluster_trim)}")
    print(f"  Offline rows (filtered): {len(df_offline_trim)}")

    cluster_set = set(map(tuple, df_cluster_trim.to_numpy()))
    offline_set = set(map(tuple, df_offline_trim.to_numpy()))

    only_in_cluster = cluster_set - offline_set
    only_in_offline = offline_set - cluster_set

    print(f"  ⚠️ {len(only_in_cluster)} rows only in cluster logs")
    print(f"  ⚠️ {len(only_in_offline)} rows only in offline logs")

    if only_in_cluster:
        print("\n  🔸 Example row only in cluster:")
        print(list(only_in_cluster)[0])

    if only_in_offline:
        print("\n  🔹 Example row only in offline:")
        print(list(only_in_offline)[0])

def main():
    run_zeek_offline()
    for log_file in LOG_FILES:
        compare_logs(CLUSTER_LOG_DIR, OFFLINE_LOG_DIR, log_file)

if __name__ == "__main__":
    main()
