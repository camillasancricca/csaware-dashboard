"""
Data xleaning operations on the ER schemas.

Leonardo Cesani, 22-11-2024
"""

# Libraries
import warnings
from Utils.data_utils import DataERPath, ERSchemas, save_csv
from Utils.Threats.threat_fox_utils import *
from Utils.Threats.url_haus_utils import *
from Utils.Threats.feodo_tracker_utils import *

# Set up logging to include a custom prefix and function name
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

# Disable warnings
warnings.filterwarnings("ignore")

class SourcesERDataCleaning:
    """
    Data Cleaning operations on the ER schemas extracted from the ER schemas.
    """
    def __init__(self):
        # Paths to ER schemas' data frames
        self.threat_fox_ER_path = DataERPath.THREAT_FOX_ER_PATH
        self.feodo_tracker_ER_path = DataERPath.FEODO_TRACKER_ER_PATH
        self.url_haus_ER_path = DataERPath.URL_HAUS_ER_PATH

    def clean_Threat_Fox(self, save_directory: str = DataERPath.THREAT_FOX_ER_PATH):
        """
        Clean the Threat Fox ER schemas.
        """
        try:
            logging.info("Starting to clean Threat Fox ER schemas...")

            # Load the ER schema data
            logging.info("Loading Threat Fox ER schemas...")
            entries_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.ENTRIES + ".csv", low_memory=False)
            tags_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.TAGS + ".csv", low_memory=False)
            alias_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.ALIAS + ".csv", low_memory=False)
            malwares_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.MALWARES + ".csv", low_memory=False)

            # Clean the ER schemas
            logging.info("Cleaning the ER schemas...")
            cleaned_entries_df = clean_ENTRIES_Threat_Fox(entries_df)
            cleaned_tag_df = clean_TAGS_Threat_Fox(tags_df)
            cleaned_alias_df = clean_ALIAS_Threat_Fox(alias_df)
            cleaned_malwares_df = clean_MALWARES_Threat_Fox(malwares_df)

            # Save the cleaned ER schemas
            logging.info("Saving cleaned Threat Fox ER schemas...")
            dataframes_dict = {
                'Entries': cleaned_entries_df,
                'Tags': cleaned_tag_df,
                'Malwares': cleaned_malwares_df,
                'Alias': cleaned_alias_df
            }

            save_csv(dataframes_dict, save_directory)
            logging.info("Finished cleaning and saving Threat Fox ER schemas.")

        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
        except pd.errors.EmptyDataError as e:
            logging.error(f"Empty data encountered: {e}")
        except Exception as e:
            logging.error(f"An error occurred while cleaning Threat Fox ER schemas: {e}")
            raise

    def clean_URL_Haus(self, save_directory: str = DataERPath.URL_HAUS_ER_PATH):
        """
        Clean the URL Haus ER schemas.
        """
        try:
            logging.info("Starting to clean URL Haus ER schemas...")

            # Load the ER schema data
            logging.info("Loading URL Haus ER schemas...")
            entries_df = pd.read_csv(self.url_haus_ER_path + ERSchemas.ENTRIES + ".csv", low_memory=False)
            tags_df = pd.read_csv(self.url_haus_ER_path + ERSchemas.TAGS + ".csv", low_memory=False)

            # Clean the ER schemas
            logging.info("Cleaning the ER schemas...")
            cleaned_entries_df = clean_ENTRIES_URL_Haus(entries_df)
            cleaned_tag_df = clean_TAGS_URL_Haus(tags_df)

            # Save the cleaned ER schemas
            logging.info("Saving cleaned URL Haus ER schemas...")
            dataframes_dict = {
                'Entries': cleaned_entries_df,
                'Tags': cleaned_tag_df,
            }

            save_csv(dataframes_dict, save_directory)
            logging.info("Finished cleaning and saving URL Haus ER schemas.")

        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
        except pd.errors.EmptyDataError as e:
            logging.error(f"Empty data encountered: {e}")
        except Exception as e:
            logging.error(f"An error occurred while cleaning URL Haus ER schemas: {e}")
            raise

    def clean_Feodo_Tracker(self, save_directory: str = DataERPath.FEODO_TRACKER_ER_PATH):
        """
        Clean the Feodo Tracker ER schemas.
        """
        try:
            logging.info("Starting to clean Feodo Tracker ER schemas...")

            # Load the ER schema data
            logging.info("Loading Feodo Tracker ER schemas...")
            entries_df = pd.read_csv(self.feodo_tracker_ER_path + ERSchemas.ENTRIES + ".csv", low_memory=False)
            malwares_df = pd.read_csv(self.feodo_tracker_ER_path + ERSchemas.MALWARES + ".csv", low_memory=False)

            # Clean the ER schemas
            logging.info("Cleaning the ER schemas...")
            cleaned_entries_df = clean_ENTRIES_Feodo_Tracker(entries_df)
            cleaned_malwares_df = clean_MALWARES_Feodo_Tracker(malwares_df)

            # Save the cleaned ER schemas
            logging.info("Saving cleaned Feodo Tracker ER schemas...")
            dataframes_dict = {
                'Entries': cleaned_entries_df,
                'Malwares': cleaned_malwares_df,
            }

            save_csv(dataframes_dict, save_directory)
            logging.info("Finished cleaning and saving Feodo Tracker ER schemas.")

        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
        except pd.errors.EmptyDataError as e:
            logging.error(f"Empty data encountered: {e}")
        except Exception as e:
            logging.error(f"An error occurred while cleaning Feodo Tracker ER schemas: {e}")
            raise

def clean_sources_ER_schemas(save_directory: str = None):
    """
       Create the ER schemas.

       :param save_directory (optional): The base directory where ER schemas will be saved.
       """
    try:
        data_cleaner = SourcesERDataCleaning()

        if save_directory is None:
            logging.info("Cleaning ER schemas...")
            data_cleaner.clean_Threat_Fox()
            data_cleaner.clean_URL_Haus()
            # data_cleaner.clean_Feodo_Tracker()
        else:
            logging.info(f"Cleaning ER schemas and saving in {save_directory}...")
            data_cleaner.clean_Threat_Fox(save_directory=save_directory + '/Threat_Fox')
            data_cleaner.clean_URL_Haus(save_directory=save_directory + '/URL_Haus')
            # data_cleaner.clean_Feodo_Tracker(save_directory=save_directory + '/Feodo_Tracker')

        logging.info("ER schemas cleaned successfully.")

    except Exception as e:
        logging.error(f"An error occurred while creating ER schemas: {e}")

# Cleaning functions for the final ER

def clean_final_ENTRIES(df):
    """
    Cleans the entries DataFrame.

    :param df: entries data frame
    :return: A cleaned DataFrame of the 'Entries' ER schema.
    """
    try:
        logging.info("Starting to clean the 'Entries' ER schema.")

        # Drop the 'status' column
        column_name = 'status'
        cleaned_ENTRIES = df.drop(columns=column_name)

        # Standardize the 'threat_type' column
        cleaned_ENTRIES['threat_type'] = cleaned_ENTRIES['threat_type'].replace('payload', 'payload delivery').replace('payload_delivery','payload delivery')

        # Normalize dates
        cleaned_ENTRIES['last_seen'] = pd.to_datetime(cleaned_ENTRIES['last_seen'], utc=True, format='mixed').dt.strftime("%Y-%m-%d")
        cleaned_ENTRIES['first_seen'] = pd.to_datetime(cleaned_ENTRIES['first_seen'], utc=True, format='mixed').dt.strftime("%Y-%m-%d")

        # Drop missing values in 'ID_ENTRY' and 'source'
        cleaned_ENTRIES = cleaned_ENTRIES.dropna(subset=['ID_ENTRY', 'source'])
        cleaned_ENTRIES = cleaned_ENTRIES.reset_index(drop=True)

        # Drop rows with 'ioc_type' as 'md5_hash' and 'sha256_hash'
        cleaned_ENTRIES = cleaned_ENTRIES.drop(cleaned_ENTRIES[(cleaned_ENTRIES['ioc_type'] == 'md5_hash') | (cleaned_ENTRIES['ioc_type'] == 'sha256_hash')].index)

        # Divide 'ioc_value' into three columns: 'ip_address', 'url', and 'domain' based on the value of 'ioc_type'
        cleaned_ENTRIES['ip_address'] = cleaned_ENTRIES.loc[cleaned_ENTRIES['ioc_type'] == 'ip:port', 'ioc']
        cleaned_ENTRIES['url'] = cleaned_ENTRIES.loc[cleaned_ENTRIES['ioc_type'] == 'url', 'ioc']
        cleaned_ENTRIES['domain'] = cleaned_ENTRIES.loc[cleaned_ENTRIES['ioc_type'] == 'domain', 'ioc']

        # Drop the 'ioc' and 'ioc_type' columns
        cleaned_ENTRIES = cleaned_ENTRIES.drop(columns=['ioc', 'ioc_type'])

        # Remove the port from the 'ip_address' column
        cleaned_ENTRIES['ip_address'] = cleaned_ENTRIES['ip_address'].str.split(':').str[0]

        return cleaned_ENTRIES

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Entries' ER schema: {e}")
        raise

def clean_final_ER(df):
    """
    Cleans the tags DataFrame.

    :param df: tags data frame
    :return: A cleaned DataFrame of the 'Tags' ER schema.
    """
    try:
        logging.info("Starting to clean the ER schema.")

        # Drop missing values in 'ID_ENTRY', 'tag', and 'source'
        df.dropna(inplace=True)
        cleaned_df = df.reset_index(drop=True)

        # Drop duplicates
        cleaned_df = cleaned_df.drop_duplicates()
        cleaned_df = cleaned_df.reset_index(drop=True)

        return cleaned_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the ER schema: {e}")
        raise

def main():
    clean_sources_ER_schemas()

if __name__ == '__main__':
    main()


