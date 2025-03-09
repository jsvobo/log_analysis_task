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
    df = df.reset_index()
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

    # Merge 'files' log based on 'conn_uid' (same as 'uid' in 'conn' log)
    if "files" in zeek_logs:
        print("Merging files...")
        files_df = zeek_logs["files"]
        merged_df = merged_df.merge(
            files_df,
            left_on="uid",
            right_on="conn_uids",
            how="left",
            suffixes=("", "_files"),
        )

    """    
    # Merge 'x509' log based on 'fuid' (same as 'fuid' in 'files' log)
    if "x509" in zeek_logs:
        print("Merging x509...")
        x509_df = zeek_logs["x509"]
        merged_df = merged_df.merge(
            x509_df, left_on="fuid", right_on="id", how="left", suffixes=("", "_x509")
        )"""

    # drop identifier columns (uid for flows, fuid for files associated)
    columns_to_drop = ["uid", "fuid"]
    merged_df.drop(
        columns=[col for col in columns_to_drop if col in merged_df.columns],
        inplace=True,
    )

    return merged_df


def preprocess_zeek_data(df):
    uint_cols = df.select_dtypes(include=["UInt16", "UInt64"]).columns.tolist()
    timedelta_cols = df.select_dtypes(include=["timedelta64[ns]"]).columns.tolist()
    cat_cols = df.select_dtypes(include=["category"]).columns.tolist()
    object_cols = df.select_dtypes(include=["object"]).columns.tolist()

    """
    # Convert UInt16 and UInt64 to standard integers
    for col in uint_cols:
        df[col] = df[col].astype("Int64")  # Keeps NaN support

    # Convert timedelta columns to seconds
    for col in timedelta_cols:
        df[col] = df[col].dt.total_seconds()

    # Convert categorical columns to string for easier handling
    for col in cat_cols:
        df[col] = df[col].astype(str).fillna("unknown")

    # Convert object columns (comma-separated lists) into actual lists
    for col in object_cols:
        df[col] = df[col].apply(lambda x: x.split(",") if isinstance(x, str) else [])

    # Fill missing values in numerical columns
    df.fillna({col: 0 for col in uint_cols + timedelta_cols}, inplace=True)

    df = pd.get_dummies(df, columns=cat_cols, drop_first=True) """

    return df


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
