import os
import subprocess
import pandas as pd

# === CONFIGURATION ===
PCAP_PATH = "/root/smallFlows.pcap"
OFFLINE_LOG_DIR = "/tmp/zeek_offline_logs"
CLUSTER_LOG_DIR = "/opt/zeek/logs/current"
LOG_FILES = ["conn.log", "dns.log", "http.log", "ssl.log"]

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
    print("✅ Zeek log generation complete.")

def read_zeek_log(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
        header_line = next(i for i, line in enumerate(lines) if line.startswith("#fields"))
        columns = lines[header_line].strip().split('\t')[1:]
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

    # Filter only fields that exist in both logs
    expected_fields = KEY_FIELDS.get(log_file, [])
    common_fields = [f for f in expected_fields if f in df_cluster.columns and f in df_offline.columns]
    if not common_fields:
        print(f"⚠️ Skipping {log_file}: no matching fields found between cluster and offline.")
        return

    df_cluster_sub = df_cluster[common_fields].dropna(how='all').drop_duplicates().sort_values(by=common_fields).reset_index(drop=True)
    df_offline_sub = df_offline[common_fields].dropna(how='all').drop_duplicates().sort_values(by=common_fields).reset_index(drop=True)

    cluster_keys = set(map(tuple, df_cluster_sub.to_numpy()))
    offline_keys = set(map(tuple, df_offline_sub.to_numpy()))

    only_in_cluster_keys = cluster_keys - offline_keys
    only_in_offline_keys = offline_keys - cluster_keys

    print(f"  ✅ Cluster filtered rows: {len(df_cluster_sub)}")
    print(f"  ✅ Offline filtered rows: {len(df_offline_sub)}")
    print(f"  ⚠️ Rows only in cluster: {len(only_in_cluster_keys)}")
    print(f"  ⚠️ Rows only in offline: {len(only_in_offline_keys)}")

    if only_in_cluster_keys:
        print(f"\n  🔸 FULL ROWS only in cluster ({len(only_in_cluster_keys)}):")
        for key in list(only_in_cluster_keys)[:5]:  # limit preview
            row = df_cluster.loc[(df_cluster[common_fields] == pd.Series(key, index=common_fields)).all(axis=1)]
            print(row.to_string(index=False))

    if only_in_offline_keys:
        print(f"\n  🔹 FULL ROWS only in offline ({len(only_in_offline_keys)}):")
        for key in list(only_in_offline_keys)[:5]:  # limit preview
            row = df_offline.loc[(df_offline[common_fields] == pd.Series(key, index=common_fields)).all(axis=1)]
            print(row.to_string(index=False))

def main():
    run_zeek_offline()
    for log_file in LOG_FILES:
        compare_logs(CLUSTER_LOG_DIR, OFFLINE_LOG_DIR, log_file)

if __name__ == "__main__":
    main()
