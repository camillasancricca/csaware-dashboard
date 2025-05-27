"""
Functions to process the Feodo Tracker data frame
"""

# Libraries
import pandas as pd
import logging
import pycountry
from Utils.data_utils import prepare_for_similarity_comparison

# CREATION OF ER SCHEMAS

def create_MALWARES_Feodo_Tracker(df):
    """
    Creates a deduplicated DataFrame of malwares with an 'unknown' type.
    Generate the MALWARE (MALWARE , type) ER schema.

    :param df: feodo tracker dataframe
    :return: A deduplicated DataFrame of malwares for Feodo Tracker.
    """
    try:
        logging.info("Starting to create the 'Malwares' ER schema for Feodo Tracker.")

        # Deduplicate malwares and reset index
        Feodo_Tracker_MALWARES_df = pd.DataFrame(df['malware']).drop_duplicates()
        Feodo_Tracker_MALWARES_df = Feodo_Tracker_MALWARES_df.reset_index(drop=True)

        # Add 'unknown' type to each malware
        Feodo_Tracker_MALWARES_df['type'] = 'unknown'

        logging.info("Finished creating the 'Malwares' ER schema for Feodo Tracker.")
        return Feodo_Tracker_MALWARES_df

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while creating the 'Malwares' ER schema for Feodo Tracker: {e}")
        raise

def create_ENTRIES_Feodo_Tracker(df):
    """
    Drops columns and organizes the DataFrame for Feodo Tracker entries.

    :param df: feodo tracker data frame
    :return: A cleaned and organized DataFrame of the 'Entries' ER schema for Feodo Tracker.
    """
    try:
        logging.info("Starting to create the 'Entries' ER schema for Feodo Tracker.")

        # Rename and add new columns
        Feodo_Tracker_ENTRIES_df = df.rename(columns={"last_online": "last_seen", "ip": "ioc"})
        Feodo_Tracker_ENTRIES_df["ioc_type"] = "ip:port"
        Feodo_Tracker_ENTRIES_df["source"] = "Feodo Tracker"
        Feodo_Tracker_ENTRIES_df['threat_type'] = 'botnet'
        Feodo_Tracker_ENTRIES_df['reference'] = 'https://feodotracker.abuse.ch/'
        Feodo_Tracker_ENTRIES_df['reporter'] = 'Feodo Tracker blocklist'
        Feodo_Tracker_ENTRIES_df['ID_ENTRY'] = Feodo_Tracker_ENTRIES_df.index

        # Reorder columns
        columns_ordered = ['ID_ENTRY', 'source', 'ioc', 'ioc_type', 'threat_type', 'malware', 'first_seen', 'last_seen', 'reporter', 'reference', 'country']
        Feodo_Tracker_ENTRIES_df = Feodo_Tracker_ENTRIES_df[columns_ordered]

        logging.info("Finished creating the 'Entries' ER schema for Feodo Tracker.")
        return Feodo_Tracker_ENTRIES_df

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while creating the 'Entries' ER schema for Feodo Tracker: {e}")
        raise

def create_IP_ADDRESSES_Feodo_Tracker(df):
    """
    Create the ER schema of IP ADRESSES starting from the columns 'ioc' and 'country'.

    :param df: feodo tracker data frame
    :return: A cleaned and organized DataFrame of the 'IP Addresses' ER schema for Feodo Tracker.
    """
    # Select columns
    ip_addresses = df[['ioc', 'country']]

    # Rename columns
    ip_addresses = ip_addresses.rename(columns={'ioc': 'ip_address'})

    # remove the port number from the ip address
    ip_addresses['ip_address'] = ip_addresses['ip_address'].str.split(':').str[0]

    return ip_addresses

def create_COUNTRIES_Feodo_Tracker(df):
    """
    Create the ER schema of COUNTRIES starting from the columns 'country',
    building a column with the complete name and one column with the abbreviation.

    :param df: feodo tracker data frame
    :return: A cleaned and organized DataFrame of the 'Countries' ER schema for Feodo Tracker.
    """

    # Create a copy of the 'country' column to avoid SettingWithCopyWarning
    countries = df[['country']].copy()

    # Function to get full country name from abbreviation
    def get_country_name(abbreviation):
        try:
            # Ensure abbreviation is treated as a string
            abbreviation = str(abbreviation).strip().upper()
            country = pycountry.countries.get(alpha_2=abbreviation)
            if country:
                return country.name
            else:
                return 'Unknown'  # Handle cases where the abbreviation is not found
        except Exception as e:
            # Print the abbreviation that caused the error for debugging purposes
            print(f"Error for abbreviation '{abbreviation}': {e}")
            return 'Unknown'

    # Apply the function to create a new column with full country names
    countries['country_full_name'] = countries['country'].apply(get_country_name)

    # Rename columns
    countries = countries.rename(columns={'country': 'country_abbreviation'})

    return countries

# CLEANING OF ER SCHEMAS

def clean_MALWARES_Feodo_Tracker(df):
    """
    Cleans the Feodo Tracker malwares DataFrame.

    :param df: feodo tracker malwares data frame
    :return: A cleaned DataFrame of the 'Malwares' ER schema for Feodo Tracker.
    """
    try:
        logging.info("Starting to clean the 'Malwares' ER schema for Feodo Tracker.")

        # Standardize the 'malware' column
        cleaned_df = prepare_for_similarity_comparison(df, 'malware', 'malware')

        logging.info("Finished cleaning the 'Malwares' ER schema for Feodo Tracker.")
        return cleaned_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Malwares' ER schema for Feodo Tracker: {e}")
        raise

def clean_ENTRIES_Feodo_Tracker(df):
    """
    Cleans the Feodo Tracker entries DataFrame.

    :param df: feodo tracker entries data frame
    :return: A cleaned DataFrame of the 'Entries' ER schema for Feodo Tracker.
    """
    try:
        logging.info("Starting to clean the 'Entries' ER schema for Feodo Tracker.")

        # Standardize the 'malware' column
        cleaned_df = prepare_for_similarity_comparison(df, 'malware', 'malware')

        logging.info("Finished cleaning the 'Entries' ER schema for Feodo Tracker.")
        return cleaned_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Entries' ER schema for Feodo Tracker: {e}")
        raise
