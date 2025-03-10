import ipaddress
import os

import numpy as np
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame


def load_zeek_log(file_path):
    """
    Parses a Zeek log file into a Pandas DataFrame using the ZAT library.
    """
    log_to_df = LogToDataFrame()
    df = log_to_df.create_dataframe(file_path)
    df["log_type"] = os.path.basename(file_path)
    df = df.reset_index()  # proper indexes, not ts (first column)
    return df


def load_all_zeek_logs(directory, ignored_files):
    """Load all Zeek log files in a directory into a dictionary of DataFrames."""
    zeek_data = {}

    for file in os.listdir(directory):
        if file in ignored_files:
            continue

        print(f"Loading {file}...")
        if file.endswith(".log"):
            file_path = os.path.join(directory, file)
            df = load_zeek_log(file_path)
            log_name = file.replace(".log", "")
            zeek_data[log_name] = df

    print("")
    return zeek_data


def merge_logs(zeek_logs, primary_log="conn"):
    """
    Merge multiple Zeek logs based on the 'uid' field.
    The primary log (e.g., 'conn') is the main dataset, and others are merged into it.
    files and x509 logs can be joined on fuid and connected to conn uid via conn_uids. this ties tzhe files to the connection logs
    """
    if primary_log not in zeek_logs:
        raise ValueError(f"Primary log {primary_log} not found in loaded logs.")

    merged_df = zeek_logs[primary_log].copy()

    for log_name, df in zeek_logs.items():
        if log_name != primary_log and "uid" in df.columns:
            print(f"Merging {log_name}...")
            suffixes = ("", f"_{log_name}")
            merged_df = merged_df.merge(df, on="uid", how="left", suffixes=suffixes)

    return merged_df


def ip_to_int(ip):
    """Convert an IP address to an integer."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # Handle invalid IPs


def convert_ip_addresses(df, ip_columns):
    """Convert IP address columns to numerical format."""
    for col in ip_columns:
        df[col] = df[col].apply(ip_to_int)
    return df
