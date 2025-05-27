"""
Data integration operations on the ER schemas.

Leonardo Cesani, 22-11-2024
"""

# Libraries
import pandas as pd
import logging
import warnings
from Utils.data_utils import DataERPath, ERSchemas, save_csv
from Scripts.Threats.data_cleaning import clean_final_ER, clean_final_ENTRIES

# Set up logging to include a custom prefix and function name
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

# Disable warnings
warnings.filterwarnings("ignore")

class ERDataIntegration:
    """
    Data integration operations on the ER schemas.
    """
    def __init__(self):
        # Paths to ER schemas' data frames
        self.threat_fox_ER_path = DataERPath.THREAT_FOX_ER_PATH
        self.feodo_tracker_ER_path = DataERPath.FEODO_TRACKER_ER_PATH
        self.url_haus_ER_path = DataERPath.URL_HAUS_ER_PATH

    def integrate(self, save_directory: str = DataERPath.SAVE_PATH):
        """
        Integrate the Threat Fox ER schemas.
        """
        try:
            logging.info("Starting to integrate Threat Fox ER schemas...")

            # Load the ER schema data from Threat Fox
            logging.info("Loading Threat Fox ER schemas...")
            Threat_Fox_ENTRIES_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.ENTRIES + ".csv", low_memory=False)
            Threat_Fox_TAGS_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.TAGS + ".csv", low_memory=False)
            Threat_Fox_ALIAS_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.ALIAS + ".csv", low_memory=False)
            Threat_Fox_MALWARES_df = pd.read_csv(self.threat_fox_ER_path + ERSchemas.MALWARES + ".csv", low_memory=False)

            # Load the ER schemas from URL Haus
            logging.info("Loading URL Haus ER schemas...")
            URL_Haus_ENTRIES_df = pd.read_csv(self.url_haus_ER_path + ERSchemas.ENTRIES + ".csv", low_memory=False)
            URL_Haus_TAGS_df = pd.read_csv(self.url_haus_ER_path + ERSchemas.TAGS + ".csv", low_memory=False)

            # Load the ER schemas from Feodo Tracker
            # logging.info("Loading Feodo Tracker ER schemas...")
            # Feodo_Tracker_ENTRIES_df = pd.read_csv(self.feodo_tracker_ER_path + ERSchemas.ENTRIES + ".csv", low_memory=False)
            # Feodo_Tracker_MALWARES_df = pd.read_csv(self.feodo_tracker_ER_path + ERSchemas.MALWARES + ".csv", low_memory=False)

            # Integrate the ER schemas
            """
            The final ER schemas have the following structure:
            - ENTRIES: final_entries_df (ID_ENTRY , source, 'ioc', 'threat_type', 'ioc_type', 'malware', 'reference', 'first_seen', 'last_seen', 'reporter')
            - TAGS: final_tags_df(ID_ENTRY, source , tag_name)
            - ALIAS: final_alias_df (malware, alias )
            - MALWARES: final_malwares_df (malware)
            """

            # Integrate the ENTRIES ER schemas
            logging.info("Integrating ENTRIES ER schemas...")
            final_ENTRIES_df = pd.DataFrame()
            # final_ENTRIES_df = pd.concat([Feodo_Tracker_ENTRIES_df, Threat_Fox_ENTRIES_df, URL_Haus_ENTRIES_df], ignore_index=True)
            final_ENTRIES_df = pd.concat([Threat_Fox_ENTRIES_df, URL_Haus_ENTRIES_df],
                                         ignore_index=True)

            # Cleaning step
            final_ENTRIES_df = clean_final_ENTRIES(final_ENTRIES_df)

            # Integrate the TAGS ER schemas
            logging.info("Integrating TAGS ER schemas...")
            final_TAGS_df = pd.DataFrame()
            final_TAGS_df = pd.concat([URL_Haus_TAGS_df, Threat_Fox_TAGS_df], ignore_index=True)

            # Cleaning step
            final_TAGS_df = clean_final_ER(final_TAGS_df)

            # Integrate the MALWARES ER schemas
            logging.info("Integrating MALWARES ER schemas...")
            final_MALWARES_df = pd.DataFrame()
            # final_MALWARES_df = pd.concat([Feodo_Tracker_MALWARES_df, Threat_Fox_MALWARES_df], ignore_index=True)
            final_MALWARES_df = pd.concat([Threat_Fox_MALWARES_df], ignore_index=True)

            # Cleaning step
            final_MALWARES_df = clean_final_ER(final_MALWARES_df)

            # Integrate the ALIAS ER schemas
            final_ALIAS_df = pd.DataFrame()
            final_ALIAS_df = pd.concat([Threat_Fox_ALIAS_df], ignore_index=True)

            # Cleaning step
            final_ALIAS_df = clean_final_ER(final_ALIAS_df)

            # Save the integrated ER schemas
            dataframes_dict = {
                'Entries' : final_ENTRIES_df,
                'Tags' : final_TAGS_df,
                'Malwares' : final_MALWARES_df,
                'Alias' : final_ALIAS_df,
                # 'IP_Addresses': pd.read_csv(self.feodo_tracker_ER_path + ERSchemas.IP_ADDRESSES + ".csv", low_memory=False),
                # 'Countries': pd.read_csv(self.feodo_tracker_ER_path + ERSchemas.COUNTRIES + ".csv", low_memory=False),
            }

            save_csv(dataframes_dict, save_directory)
        except Exception as e:
            logging.error(f"Error during integration of Threat Fox ER schemas: {e}")

def integrate_ER_schemas(save_directory: str = DataERPath.SAVE_PATH):
    """
    Integrate the ER schemas.
    """
    data_integrator = ERDataIntegration()
    try:
        logging.info(f"Integrating ER schemas and saving in {save_directory}...")
        data_integrator.integrate(save_directory)
    except Exception as e:
        logging.error(f"Error during integration of ER schemas: {e}")

if __name__ == "__main__":
    integrate_ER_schemas()