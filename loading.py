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

    return zeek_data


def merge_logs(zeek_logs, primary_log="conn"):
    """
    Merge multiple Zeek logs based on the 'uid' field.
    The primary log (e.g., 'conn') is the main dataset, and others are merged into it.
    """
    if primary_log not in zeek_logs:
        raise ValueError(f"Primary log {primary_log} not found in loaded logs.")

    merged_df = zeek_logs[primary_log].copy()

    for log_name, df in zeek_logs.items():
        if log_name != primary_log and "uid" in df.columns:
            print(f"Merging {log_name}...")
            print("columns of the new logfile: ", df.columns)
            suffixes = ("", f"_{log_name}")
            merged_df = merged_df.merge(df, on="uid", how="left", suffixes=suffixes)

    return merged_df


def preprocess_zeek_data(df):
    """Run all preprocessing steps on Zeek data."""
    # df = convert_timestamps(df, "ts")
    df = encode_categorical(df, ["proto", "service", "conn_state"])
    df = fill_missing_values(df)
    df = convert_ip_addresses(df, ["id.orig_h", "id.resp_h"])
    return df


def convert_timestamps(df, column="ts"):
    """Convert Zeek timestamps to datetime format."""
    df[column] = pd.to_datetime(df[column], unit="s")
    return df


def encode_categorical(df, categorical_cols):
    """One-hot encode categorical columns."""
    df = pd.get_dummies(df, columns=categorical_cols)
    return df


def fill_missing_values(df):
    """Fill missing values with 0."""
    return df.fillna(0)


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
