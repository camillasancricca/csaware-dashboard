"""
Creation of the ER schemas starting from row csv files

Leonardo Cesani, 16-11-2024
"""

# Libraries
from Utils.data_utils import DataSource, DataSourcesPaths, DataERPath, save_csv
from Utils.Threats.threat_fox_utils import *
from Utils.Threats.url_haus_utils import *
from Utils.Threats.feodo_tracker_utils import *

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

class ERSchemaCreation:
    """
    Create the ER schemas starting from row data frames.
    """
    def __init__(self):
        # Paths to data frames
        self.threat_fox_data_path = DataSourcesPaths.THREAT_FOX + DataSource.THREAT_FOX + ".csv"
        self.feodo_tracker_data_path = DataSourcesPaths.FEODO_TRACKER + DataSource.FEODO_TRACKER + ".csv"
        self.url_haus_data_path = DataSourcesPaths.URL_HAUS +  DataSource.URL_HAUS + ".csv"

    def ER_Threat_Fox(self, save_directory: str = DataERPath.THREAT_FOX_ER_PATH):
        """
        Loads Threat Fox data, creates multiple ER schemas (Tags, Alias, Malwares, Entries), and saves them as CSV files.

        :param save_directory: path to the save directory
        """
        try:
            # Read the CSV
            logging.info("Loading Threat Fox data...")
            df = pd.read_csv(self.threat_fox_data_path, low_memory=False)

            # Column filtering
            logging.info("Filtering columns...")
            df = df.drop('Unnamed: 0', axis=1, errors='ignore')
            df = df.drop(['threat_type_desc', 'ioc_type_desc', 'malware', 'confidence_level'], axis=1, errors='ignore')

            # TAGS (ENTRY_ID, SOURCE , tag_name) ER creation
            logging.info("Creating TAGS ER schema...")
            tags_df = create_TAGS_Threat_Fox(df)

            # ALIAS (MALWARE , ALIAS) ER creation
            logging.info("Creating ALIAS ER schema...")
            alias_df = create_ALIAS_Threat_Fox(df)

            # MALWARES (MALWARE_NAME) ER creation
            logging.info("Creating MALWARES ER schema...")
            malwares_df = create_MALWARES_Threat_Fox(alias_df)

            # ENTRIES (D_ENTRY, SOURCE, ioc, ioc_type, threat_type, malware, first_seen, last_seen, reporter, reference) ER creation
            logging.info("Creating ENTRIES ER schema...")
            entries_df = create_ENTRIES_Threat_Fox(df)

            # Save the ER schemas
            logging.info("Saving ER schemas...")
            dataframes_dict = {
                'Entries': entries_df,
                'Tags': tags_df,
                'Malwares': malwares_df,
                'Alias': alias_df
            }

            save_csv(dataframes_dict, save_directory)
            logging.info("Threat Fox ER schemas saved successfully.")

        except FileNotFoundError:
            logging.error(f"Data file {self.threat_fox_data_path} not found. Please make sure the file path is correct.")
        except pd.errors.EmptyDataError:
            logging.error("The data file is empty. Please provide a valid data file.")
        except Exception as e:
            logging.error(f"An error occurred while processing Threat Fox data: {e}")

    def ER_URL_Haus(self, save_directory: str = DataERPath.URL_HAUS_ER_PATH):
        """
        Processes URL Haus data to create ER schemas (Entries and Tags) and saves them as CSV files.

        :param save_directory: path to the save directory
        """
        try:
            # Read the CSV
            logging.info("Loading URL Haus data...")
            df = pd.read_csv(self.url_haus_data_path, low_memory=False)

            # Column filtering
            logging.info("Filtering columns...")
            df = df.drop('Unnamed: 0', axis=1, errors='ignore')

            # Rename columns
            logging.info("Renaming columns...")
            df = df.rename(columns={
                '# id': 'ID_ENTRY',
                'url': 'ioc',
                'url_status': 'status',
                'dateadded': 'first_seen',
                'last_online': 'last_seen',
                'urlhaus_link': 'reference',
                'threat': 'threat_type'
            })

            # ENTRIES ER creation
            logging.info("Creating ENTRIES ER schema...")
            entries_df = create_ENTRIES_Url_Haus(df)

            # TAGS ER creation
            logging.info("Creating TAGS ER schema...")
            tags_df = create_TAGS_Url_Haus(df)

            # Save the ER Schemas
            logging.info("Saving ER schemas...")
            dataframes_dict = {
                'Entries': entries_df,
                'Tags': tags_df
            }

            save_csv(dataframes_dict, save_directory)
            logging.info("URL Haus ER schemas saved successfully.")

        except FileNotFoundError:
            logging.error(f"Data file {self.url_haus_data_path} not found. Please make sure the file path is correct.")
        except pd.errors.EmptyDataError:
            logging.error("The data file is empty. Please provide a valid data file.")
        except Exception as e:
            logging.error(f"An error occurred while processing URL Haus data: {e}")

    def ER_Feodo_Tracker(self, save_directory: str = DataERPath.FEODO_TRACKER_ER_PATH):
        """
        Processes Feodo Tracker data to create ER schemas (Malwares and Entries) and saves them as CSV files.

        :param save_directory: path to the save directory
        """
        try:
            # Read the CSV
            logging.info("Loading Feodo Tracker data...")
            df = pd.read_csv(self.feodo_tracker_data_path, low_memory=False)

            # Column filtering
            logging.info("Filtering columns...")
            df = df.drop('Unnamed: 0', axis=1, errors='ignore')
            df = df.drop(['hostname', 'as_number', 'as_name'], axis=1, errors='ignore')

            # Merge columns ip-address and port into a single column
            logging.info("Merging IP address and port columns...")
            df['ip'] = df['ip_address'].astype(str).str.cat(df['port'].astype(str), sep=':')
            df = df.drop(['ip_address', 'port'], axis=1, errors='ignore')

            # MALWARES ER creation
            logging.info("Creating MALWARES ER schema...")
            malwares_df = create_MALWARES_Feodo_Tracker(df)

            # ENTRIES ER creation
            logging.info("Creating ENTRIES ER schema...")
            entries_df = create_ENTRIES_Feodo_Tracker(df)

            # IP ADDRESSES ER creation
            logging.info("Creating IP ADDRESSES ER schema...")
            ip_addresses_df = create_IP_ADDRESSES_Feodo_Tracker(entries_df)

            # COUNTRIES ER creation
            logging.info("Creating COUNTRIES ER schema...")
            countries_df = create_COUNTRIES_Feodo_Tracker(entries_df)

            # Save ER schemas
            logging.info("Saving ER schemas...")
            dataframes_dict = {
                'Entries': entries_df,
                'Malwares': malwares_df,
                'IP_Addresses': ip_addresses_df,
                'Countries': countries_df
            }

            save_csv(dataframes_dict, save_directory)
            logging.info("Feodo Tracker ER schemas saved successfully.")

        except FileNotFoundError:
            logging.error(f"Data file {self.feodo_tracker_data_path} not found. Please make sure the file path is correct.")
        except pd.errors.EmptyDataError:
            logging.error("The data file is empty. Please provide a valid data file.")
        except Exception as e:
            logging.error(f"An error occurred while processing Feodo Tracker data: {e}")


def create_ER_schemas(save_directory: str = None):
    """
    Create the ER schemas.

    :param save_directory: The base directory where ER schemas will be saved.
    """
    try:
        schema_creator = ERSchemaCreation()

        if save_directory is None:
            logging.info("Creating ER schemas with default save directories...")
            schema_creator.ER_Threat_Fox()
            schema_creator.ER_URL_Haus()
            schema_creator.ER_Feodo_Tracker()
        else:
            logging.info(f"Creating ER schemas with custom save directory: {save_directory}")
            schema_creator.ER_Threat_Fox(save_directory=save_directory + '/Threat_Fox')
            schema_creator.ER_URL_Haus(save_directory=save_directory + '/URL_Haus')
            # schema_creator.ER_Feodo_Tracker(save_directory=save_directory + '/Feodo_Tracker')

        logging.info("ER schemas created successfully.")

    except Exception as e:
        logging.error(f"An error occurred while creating ER schemas: {e}")

def main():
    create_ER_schemas()

if __name__ == '__main__':
    main()

