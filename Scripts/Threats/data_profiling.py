"""
Data profiling for the ER schemas.

Leonardo Cesani, 18-11-2024
"""

# Libraries
import pandas as pd

import logging
from  ydata_profiling import ProfileReport
from Utils.data_utils import FinalDataERPath, ERSchemas
import warnings

# Set up logging to include a custom prefix and function name
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

# Disable warnings
warnings.filterwarnings("ignore")

class DataProfiling:
    """
    Perform data profiling on a specified ER schema.
    """
    def __init__(self, er_schema: str):
        """
        Initialize DataProfiling with specified data source and ER schema.
        """
        self.data_path = FinalDataERPath.SAVE_PATH
        self.er_schema = er_schema
        if er_schema not in ERSchemas.__dict__.values():
            raise ValueError(f"ER schema {er_schema} not found in ERSchemas.")

        # Load data
        self.df = self.load_data()

    def load_data(self):
        """
        Load data from the specified ER schema.
        """
        logging.info(f"Loading data from {self.er_schema} ER schema.")
        return pd.read_csv(self.data_path + self.er_schema + ".csv")

    def profile(self):
        """
        Perform data profiling on the loaded data.
        """
        if self.er_schema == ERSchemas.ENTRIES:
            self.df['first_seen'] = pd.to_datetime(self.df['first_seen'],format='mixed', errors='coerce')
            self.df['last_seen'] = pd.to_datetime(self.df['last_seen'],format='mixed', errors='coerce')
        logging.info(f"Performing data profiling on {self.er_schema} ER schema.")
        # Proceed with the data profiling
        profile = ProfileReport(self.df, title=f"{self.er_schema} ER Schema Profiling Report", explorative=True)
        profile.to_file(f"{self.data_path}/Profiles/{self.er_schema}_profiling_report.json")

        logging.info(f"Data profiling completed for {self.er_schema} ER schema. Report saved to profiles/{self.er_schema}_profiling_report.json.")


def profile_ER_schema(er_schema: str = ERSchemas.ENTRIES):
    """
    Perform data profiling on all ER schemas.
    """
    dp = DataProfiling(er_schema)
    dp.profile()

if __name__ == "__main__":
    er_schemas = [ERSchemas.ENTRIES, ERSchemas.MALWARES, ERSchemas.TAGS, ERSchemas.ALIAS]
    for er_schema in er_schemas:
        profile_ER_schema(er_schema)

