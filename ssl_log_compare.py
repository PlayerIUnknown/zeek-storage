# Install wireshark for mergecap

import os
import subprocess
import pandas as pd
import argparse

# === CONFIGURATION ===
CLUSTER_LOG_DIR = "/opt/zeek/logs/current"
SSL_LOG_FILE = "ssl.log"
OUTPUT_DIR = "/tmp/zeek_ssl_comparison"

def run_mergecap(pcap_files, output_pcap):
    """Combine multiple pcap files into one using mergecap"""
    print(f"📦 Merging pcap files: {pcap_files}")
    cmd = ["mergecap", "-w", output_pcap] + pcap_files
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print("❌ mergecap failed:", result.stderr.decode())
        exit(1)
    else:
        print(f"✅ Merged pcap saved to {output_pcap}")

def run_zeek(pcap_file, output_dir):
    """Run Zeek on the merged pcap file and generate logs"""
    print(f"📦 Running Zeek on merged pcap file {pcap_file}...")
    os.makedirs(output_dir, exist_ok=True)
    
    # Run Zeek with the correct cwd (working directory)
    cmd = ["zeek", "-C", "-r", pcap_file]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=output_dir)

    if result.returncode != 0:
        print("❌ Zeek failed:", result.stderr.decode())
        exit(1)
    else:
        print(f"✅ Zeek log generation complete in {output_dir}")

def read_zeek_log(filepath):
    """Read a Zeek log file and return a DataFrame"""
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
    """Compare the cluster and offline ssl.log files"""
    print(f"\n🔍 Comparing {log_file}")
    cluster_log_path = os.path.join(cluster_dir, log_file)
    offline_log_path = os.path.join(offline_dir, log_file)

    if not os.path.exists(cluster_log_path) or not os.path.exists(offline_log_path):
        print(f"⚠️ Missing {log_file} in one or both directories.")
        return

    df_cluster = read_zeek_log(cluster_log_path)
    df_offline = read_zeek_log(offline_log_path)
    if df_cluster is None or df_offline is None:
        return

    # Define key fields to compare for ssl.log
    key_fields = ["version", "cipher", "server_name", "validation_status"]
    common_fields = [f for f in key_fields if f in df_cluster.columns and f in df_offline.columns]
    if not common_fields:
        print(f"⚠️ Skipping {log_file}: no matching fields found between cluster and offline logs.")
        return

    # Filter the logs and perform the comparison
    df_cluster_sub = df_cluster[common_fields].dropna(how='all').drop_duplicates().sort_values(by=common_fields).reset_index(drop=True)
    df_offline_sub = df_offline[common_fields].dropna(how='all').drop_duplicates().sort_values(by=common_fields).reset_index(drop=True)

    cluster_keys = set(map(tuple, df_cluster_sub.to_numpy()))
    offline_keys = set(map(tuple, df_offline_sub.to_numpy()))

    only_in_cluster_keys = cluster_keys - offline_keys
    only_in_offline_keys = offline_keys - cluster_keys

    print(f"  📄 Total cluster rows: {len(df_cluster)}")
    print(f"  📄 Total offline rows: {len(df_offline)}")
    print(f"  ✅ Cluster filtered rows (deduplicated): {len(df_cluster_sub)}")
    print(f"  ✅ Offline filtered rows (deduplicated): {len(df_offline_sub)}")
    print(f"  ⚠️ Rows only in cluster: {len(only_in_cluster_keys)}")
    print(f"  ⚠️ Rows only in offline: {len(only_in_offline_keys)}")

    if only_in_cluster_keys:
        print(f"\n  🔸 FULL ROWS only in cluster ({min(len(only_in_cluster_keys), 5)} shown):")
        for key in list(only_in_cluster_keys)[:5]:
            row = df_cluster.loc[(df_cluster[common_fields] == pd.Series(key, index=common_fields)).all(axis=1)]
            print(row.to_string(index=False))

    if only_in_offline_keys:
        print(f"\n  🔹 FULL ROWS only in offline ({min(len(only_in_offline_keys), 5)} shown):")
        for key in list(only_in_offline_keys)[:5]:
            row = df_offline.loc[(df_offline[common_fields] == pd.Series(key, index=common_fields)).all(axis=1)]
            print(row.to_string(index=False))

def main():
    parser = argparse.ArgumentParser(description="Compare ssl.log between Zeek cluster and merged pcap files")
    parser.add_argument('pcap_files', nargs='+', help="Paths to the pcap files to compare")
    args = parser.parse_args()

    # Generate merged pcap file using mergecap
    merged_pcap = "/tmp/merged.pcap"
    run_mergecap(args.pcap_files, merged_pcap)

    # Run Zeek on the merged pcap and generate logs
    temp_dir = "/tmp/zeek_temp_dir"
    run_zeek(merged_pcap, temp_dir)

    # Compare ssl.log between cluster and offline logs
    compare_logs(CLUSTER_LOG_DIR, temp_dir, SSL_LOG_FILE)

if __name__ == "__main__":
    main()
