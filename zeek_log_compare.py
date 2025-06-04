import os
import subprocess
import pandas as pd

# === CONFIGURATION ===
PCAP_PATH = "/root/test.pcap"
OFFLINE_LOG_DIR = "/tmp/zeek_offline_logs"
CLUSTER_LOG_DIR = "/opt/zeek/logs/current"
LOG_FILES = ["conn.log", "dns.log", "http.log", "ssl.log"]

def run_zeek_offline():
    print(f"📦 Running Zeek offline on {PCAP_PATH}...")
    os.makedirs(OFFLINE_LOG_DIR, exist_ok=True)

    # Clean previous logs
    for file in os.listdir(OFFLINE_LOG_DIR):
        os.remove(os.path.join(OFFLINE_LOG_DIR, file))

    cmd = [
        "zeek", "-C", "-r", PCAP_PATH,
        f"Log::default_path={OFFLINE_LOG_DIR}"
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
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

    # Sort by timestamp if available
    if 'ts' in df_cluster.columns:
        df_cluster = df_cluster.sort_values('ts')
        df_offline = df_offline.sort_values('ts')

    print(f"\n🔍 Comparing {log_file}")
    print(f"  Cluster rows : {len(df_cluster)}")
    print(f"  Offline rows : {len(df_offline)}")

    # Find rows that are different
    df_combined = pd.concat([df_cluster, df_offline])
    df_diff = df_combined.drop_duplicates(keep=False)

    if df_diff.empty:
        print("  ✅ No differences found.")
    else:
        print(f"  ⚠️ {len(df_diff)} differing rows found. Sample:")
        print(df_diff.head(5).to_string(index=False))

def main():
    run_zeek_offline()
    for log_file in LOG_FILES:
        compare_logs(CLUSTER_LOG_DIR, OFFLINE_LOG_DIR, log_file)

if __name__ == "__main__":
    main()
