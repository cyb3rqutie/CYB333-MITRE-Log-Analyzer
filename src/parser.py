"""
parser.py

Reads and loads Windows event log data from a CSV file.
"""

import pandas as pd


def load_logs(file_path):
    """
    Load log data from a CSV file.

    Args:
        file_path (str): Path to the CSV file

    Returns:
        pandas.DataFrame
    """

    try:
        logs = pd.read_csv(file_path)
        return logs

    except Exception as error:
        print(f"Error loading file: {error}")
        return None
