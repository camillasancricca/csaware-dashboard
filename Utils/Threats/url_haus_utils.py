"""
Functions to process the URL Haus data frame
"""

# Libraries
import logging
from Utils.data_utils import prepare_for_similarity_comparison

# CREATION OF ER SCHEMAS

def create_ENTRIES_Url_Haus(df):
    """
    Adds a 'source' column and reorders columns for URL Haus entries DataFrame.
    :param df: url haus data frame
    :return: A DataFrame with ordered columns for URL Haus entries.
    """
    try:
        logging.info("Starting to create the 'Entries' ER schema for URL Haus.")

        # Add source column
        df['source'] = 'URL Haus'
        ordered_columns = ['ID_ENTRY', 'source', 'ioc', 'threat_type', 'first_seen', 'last_seen', 'status', 'reporter',
                           'reference']
        URL_HAUS_Entries_df = df[ordered_columns]

        logging.info("Finished creating the 'Entries' ER schema for URL Haus.")
        return URL_HAUS_Entries_df

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while creating the 'Entries' ER schema for URL Haus: {e}")
        raise

def create_TAGS_Url_Haus(df):
    """
    Selects and renames columns to create the Tags DataFrame for URL Haus entries.
    :param df: url haus data frame
    :return: A DataFrame with selected and renamed columns for URL Haus tags.
    """
    try:
        logging.info("Starting to create the 'Tags' ER schema for URL Haus.")

        ordered_tags_columns = ['ID_ENTRY', 'source', 'tags']
        URL_HAUS_Tags_df = df[ordered_tags_columns]
        URL_HAUS_Tags_df = URL_HAUS_Tags_df.rename(columns={'tags': 'tag'})

        logging.info("Finished creating the 'Tags' ER schema for URL Haus.")
        return URL_HAUS_Tags_df

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while creating the 'Tags' ER schema for URL Haus: {e}")
        raise

# CLEANING OF ER SCHEMAS

def clean_ENTRIES_URL_Haus(df):
    """
    Cleans the URL Haus Entries ER schema.
    :param df: url haus data frame
    :return: A cleaned DataFrame of the 'Entries' ER schema for URL Haus.
    """
    try:
        logging.info("Starting to clean the 'Entries' ER schema for URL Haus.")

        # Drop NaNs and impute missing values for 'last_seen'
        logging.info("Imputing missing values for 'last_seen' based on 'first_seen'...")
        df['last_seen'].where(~(df.last_seen.isnull()), other=df.first_seen, inplace=True)

        # Standardize the field 'threat_type'
        logging.info("Standardizing the 'threat_type' field...")
        df.loc[df['threat_type'] == 'malware_download', 'threat_type'] = 'payload_delivery'

        # Reorder columns
        ordered_columns = ['ID_ENTRY', 'source', 'ioc', 'threat_type', 'first_seen', 'last_seen', 'status', 'reporter',
                           'reference']
        URL_Haus_ENTRIES_df = df[ordered_columns]

        logging.info("Finished cleaning the 'Entries' ER schema for URL Haus.")
        return URL_Haus_ENTRIES_df

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Entries' ER schema for URL Haus: {e}")
        raise

def clean_TAGS_URL_Haus(df):
    """
    Cleans the URL Haus Tags ER schema.
    :param df: url haus data frame
    :return: A cleaned DataFrame of the 'Tags' ER schema for URL Haus.
    """
    try:
        logging.info("Starting to clean the 'Tags' ER schema for URL Haus.")

        # Drop NaNs
        logging.info("Dropping NaN values from the DataFrame...")
        df = df.dropna().reset_index(drop=True)

        # Standardize the field 'tag'
        logging.info("Standardizing the 'tag' field for similarity comparison...")
        URL_Haus_TAGS_df = prepare_for_similarity_comparison(df, 'tag', 'tag')

        logging.info("Finished cleaning the 'Tags' ER schema for URL Haus.")
        return URL_Haus_TAGS_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Tags' ER schema for URL Haus: {e}")
        raise
