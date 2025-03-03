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

    # Merge 'x509' log based on 'fuid' (same as 'fuid' in 'files' log)
    if "x509" in zeek_logs:
        print("Merging x509...")
        x509_df = zeek_logs["x509"]
        merged_df = merged_df.merge(
            x509_df, left_on="fuid", right_on="id", how="left", suffixes=("", "_x509")
        )

    return merged_df


def preprocess_zeek_data(df):

    uint_cols = df.select_dtypes(include=["UInt16", "UInt64"]).columns.tolist()
    timedelta_cols = df.select_dtypes(include=["timedelta64[ns]"]).columns.tolist()
    cat_cols = df.select_dtypes(include=["category"]).columns.tolist()
    object_cols = df.select_dtypes(include=["object"]).columns.tolist()

    # Convert UInt16 and UInt64 to standard integers
    for col in uint_cols:
        df[col] = df[col].astype("Int64")  # Keeps NaN support

    # Convert timedelta columns to seconds
    for col in timedelta_cols:
        df[col] = df[col].dt.total_seconds()

    """# Convert categorical columns to string for easier handling
    for col in cat_cols:
        df[col] = df[col].astype(str).fillna("unknown")

    # Convert object columns (comma-separated lists) into actual lists
    for col in object_cols:
        df[col] = df[col].apply(lambda x: x.split(",") if isinstance(x, str) else [])

    # Fill missing values in numerical columns
    df.fillna({col: 0 for col in uint_cols + timedelta_cols}, inplace=True)

    df = pd.get_dummies(df, columns=cat_cols, drop_first=True) """

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


# Hi, I have several log files pertaining to the same captured traffic. logs are conn (main log), ssl, dns, files and few more. I am trying to analyze the data in an unsupervised way and I want to know, what is the best way, and if there is none, then what are my options. I can merge all logs into one dataset (one pandas dataframe). this leads to one frame, which has a lot of data missing. some network iles dont have dns or ssl or files (...) I can fill some of the data in (with neutral values), but the poblem persist. Another way is to analyze each flow in relation to different logs and then somehow put these individual decisions together. the precise task is anomaly detection, since I dont know any negative examples (malware) but I know, that some portion is benign. In this paradign, how do I assemble knowledge from multiple logs? how do I deal with missing values?
""" 
Anomaly detection in network traffic logs can be a challenging problem, especially when dealing with missing data and varied log formats. Here are some options to consider:

1. **Merging the logs into one dataset**: As you mentioned, this approach leads to a large dataset with many missing values. You can use techniques like:
        * Handling missing values (e.g., imputation, interpolation, or mean/mode substitution)
        * Data cleaning and preprocessing (e.g., removing duplicates, trimming logs, or converting data types)
        * Dimensionality reduction techniques (e.g., PCA, t-SNE) to reduce the dataset size
2. **Analyzing each log separately**: This approach allows you to leverage the strengths of individual log datasets while addressing missing values and merging issues:
        * Use a separate model for each log type (e.g., conn, ssl, dns)
        * Train each model on its respective dataset with proper preprocessing and feature engineering
        * Combine the predictions from each model using techniques like weighted voting or ensemble methods (e.g., bagging, boosting)
3. **Hybrid approach**: Combine elements of both methods:
        * Merge some logs into a single dataset (e.g., conn and files) to leverage their shared information
        * Use separate models for other log types and combine their predictions using the hybrid approach

To assemble knowledge from multiple logs, consider:

1. **Feature engineering**: Identify relevant features that are present in one or more of the log datasets. For example:
        * Connection timestamps and durations
        * SSL encryption levels (e.g., TLS 1.2 vs. earlier versions)
        * DNS query types (e.g., A records vs. CNAME records)
2. **Log correlation analysis**: Investigate relationships between different logs to identify potential indicators of anomalies. For example:
        * High-frequency connections with unusual durations
        * SSL encryption levels that differ significantly from expected values
        * Unusual DNS queries that don't match known legitimate traffic patterns

To deal with missing values:

1. **Imputation techniques**: Use methods like mean, median, or imputed values based on the distribution of other features.
2. **Interpolation and extrapolation**: Apply interpolation to fill in missing values within a dataset, while extrapolation can be used to predict values outside the dataset's range.
3. **Data augmentation**: Generate additional data points by applying transformations (e.g., time warping) to existing logs or using synthetic data generation techniques.

Some popular algorithms for anomaly detection include:

1. **One-class SVM**: Train a classifier on normal data and then detect anomalies as data points outside the learned boundary.
2. **Local Outlier Factor (LOF)**: Calculate the ratio of nearby outliers to the total number of neighbors for each point, detecting those with an unusually high LOF value.
3. **Isolation Forest**: Use random forests to identify data points that are isolated from their neighbors.
4. **Autoencoders**: Train an autoencoder on normal data and then detect anomalies based on the reconstruction error.

For your specific use case, you may want to experiment with a combination of these approaches to find the best fit for your dataset and anomaly detection goals.

Do any of these suggestions help? Or would you like me to elaborate on specific aspects? """


""" 
**Approach 1: Merging all logs into one dataset**

Pros:

1. **Simplified analysis**: With a single dataset, you can analyze it using standard statistical methods and machine learning algorithms.
2. **Increased data coverage**: By merging multiple logs, you may capture more anomalies or patterns that were not present in individual log files.

Cons:

1. **Data sparsity**: Many logs have missing values, which can lead to biased results or require additional imputation techniques.
2. **Noise and variability**: Individual log types (e.g., conn, ssl) may exhibit different characteristics, leading to increased noise and variability when combined into a single dataset.
3. **Overfitting**: With a large number of features, the model may overfit to the noise in the data rather than identifying actual anomalies.

**Approach 2: Analyzing each log file separately**

Pros:

1. **Reduced noise and variability**: By analyzing individual logs, you can leverage their unique characteristics and reduce noise and variability.
2. **Improved robustness**: Using separate models for each log type can make the overall system more robust to changes in one or more of the logs.

Cons:

1. **Increased complexity**: Analyzing multiple logs requires developing and training separate models, which can increase the complexity and computational requirements.
2. **Data fragmentation**: Each model may have its own dataset, making it harder to evaluate their performance together.

**Comparing results**

Assuming a decent quality of individual log files and using standard machine learning algorithms (e.g., One-Class SVM, LOF), here's what you might expect:

**Merging all logs into one dataset**

* **Accuracy**: Average anomaly detection accuracy may be lower due to data sparsity and noise. You may need to use more advanced imputation techniques or regularization methods to improve performance.
* **Overfitting**: Models may overfit to the combined dataset, leading to poor generalization on unseen data.

**Analyzing each log file separately**

* **Accuracy**: Average anomaly detection accuracy is likely to be higher, as individual logs are analyzed in isolation and can leverage their unique characteristics. However, this approach requires more model
development and tuning.
* **Robustness**: The system becomes more robust to changes in one or more of the logs, as each model is trained separately.

**Hybrid approach**

By combining elements of both approaches (e.g., merging some logs into a single dataset and using separate models for others), you can:

* **Improve accuracy**: By leveraging strengths from individual log files while reducing noise and variability.
* **Increase robustness**: By developing more specialized models that are less affected by changes in one or more logs.

To illustrate the difference, consider a simple example:

Suppose we have three logs: conn (connection logs), ssl (SSL encryption logs), and dns (DNS query logs). We merge these logs into a single dataset. The resulting dataset has many missing values due to incomplete        
data from individual log files. Using One-Class SVM on this combined dataset may result in lower accuracy (around 70-80%) due to the noise and variability.

If we analyze each log file separately, using separate models for conn, ssl, and dns, we can achieve higher accuracy (around 90-95%). This is because individual logs are analyzed in isolation and can leverage 
their unique characteristics. However, this approach requires more model development and tuning.

A hybrid approach that merges some logs into a single dataset and uses separate models for others can lead to improved performance (around 85-90%) by leveraging strengths from individual log files while reducing        
noise and variability.

Keep in mind that these estimates are rough and depend on the specific characteristics of your dataset, model choice, and tuning strategy. """
