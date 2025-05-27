"""
Functions to process the Threat Fox data frame
"""

# Libraries
import pandas as pd
import numpy as np
import logging
from Utils.data_utils import prepare_for_similarity_comparison

# SPLIT FUNCTIONS

def split_tags(row):
    row["tags"] = str(row["tags"]).replace('[','').replace(']','').replace("'",'').split(",")
    return pd.Series(row['tags'])

def split_alias(row):
    row["malware_alias"] = str(row["malware_alias"]).split(",")
    return pd.Series(row['malware_alias'])

# CREATION OF ER SCHEMAS

def create_TAGS_Threat_Fox(df):
    """
    Splits and reshapes a DataFrame's 'tags' column into individual rows linked to their 'ID_ENTRY'.
    Generate the TAGS (ENTRY_ID, SOURCE , tag_name) ER schema.

    :param df: threat fox data frame
    :return: A cleaned DataFrame of the 'Tags' ER schema for Threat Fox.
    """
    try:
        logging.info("Starting to create the 'Tags' ER schema for Threat Fox.")

        tags = pd.DataFrame(df[['id', 'tags']])

        # Apply the function to the DataFrame
        logging.info("Splitting tags column...")
        new_df = tags.apply(split_tags, axis=1).rename(columns=lambda x: f"tags{x + 1}")

        # Merge the new DataFrame with the original DataFrame
        tags = pd.concat([tags, new_df], axis=1).drop('tags', axis=1)
        tags = tags.rename(columns={"id": "ID_ENTRY"})

        # Reshape the DataFrame
        columns = list(tags.columns)
        new_df = pd.DataFrame()

        for i, col in enumerate(columns):
            if col != 'ID_ENTRY':
                tmp_df = tags[['ID_ENTRY', col]].rename(columns={col: 'tag'})
                new_df = pd.concat([new_df, tmp_df], axis=0)

        Threat_Fox_TAGS_df = new_df

        # Add source and clean up the DataFrame
        Threat_Fox_TAGS_df['source'] = 'Threat Fox'
        Threat_Fox_TAGS_df = Threat_Fox_TAGS_df.sort_values(by='ID_ENTRY')
        Threat_Fox_TAGS_df = Threat_Fox_TAGS_df.dropna(subset=['tag'], axis=0)
        Threat_Fox_TAGS_df = Threat_Fox_TAGS_df.reset_index(drop=True)
        Threat_Fox_TAGS_df = Threat_Fox_TAGS_df[['ID_ENTRY', 'source', 'tag']]

        logging.info("Finished creating the 'Tags' ER schema for Threat Fox.")
        return Threat_Fox_TAGS_df

    except Exception as e:
        logging.error(f"An error occurred while creating the 'Tags' ER schema for Threat Fox: {e}")
        raise

def create_ALIAS_Threat_Fox(df):
    """
    Splits and reshapes a DataFrame's 'malware_alias' column into individual rows linked to their 'malware'.
    Generate the ALIAS (MALWARE , ALIAS) ER schema.

    :param df: threat fox data frame
    :return: A cleaned DataFrame of the 'Alias' ER schema for Threat Fox.
    """
    try:
        logging.info("Starting to create the 'Alias' ER schema for Threat Fox.")

        alias = pd.DataFrame(df[['malware_printable', 'malware_alias']])

        # Apply the function to the DataFrame
        logging.info("Splitting malware_alias column...")
        new_df = alias.apply(split_alias, axis=1).rename(columns=lambda x: f"alias{x + 1}")
        alias = pd.concat([alias, new_df], axis=1).drop('malware_alias', axis=1)
        alias = alias.rename(columns={"malware_printable": "malware"})

        # Reshape the DataFrame
        columns = list(alias.columns)
        new_df = pd.DataFrame()

        for i, col in enumerate(columns):
            if col != 'malware':
                tmp_df = alias[['malware', col]].rename(columns={col: 'alias'})
                new_df = pd.concat([new_df, tmp_df], axis=0, ignore_index=True)

        Threat_Fox_ALIAS_df = new_df
        Threat_Fox_ALIAS_df = Threat_Fox_ALIAS_df.reset_index(drop=True)

        logging.info("Finished creating the 'Alias' ER schema for Threat Fox.")
        return Threat_Fox_ALIAS_df

    except Exception as e:
        logging.error(f"An error occurred while creating the 'Alias' ER schema for Threat Fox: {e}")
        raise

def create_MALWARES_Threat_Fox(df):
    """
    Creates a deduplicated DataFrame of malwares with an 'unknown' type.
    Generate the MALWARE (MALWARE , type) ER schema.

    :param df: ALIAS dataframe
    :return: A cleaned DataFrame of the 'Malwares' ER schema for Threat Fox.
    """
    try:
        logging.info("Starting to create the 'Malwares' ER schema for Threat Fox.")

        # Deduplicate malwares and reset index
        Threat_Fox_MALWARES_df = pd.DataFrame(df['malware']).drop_duplicates()
        Threat_Fox_MALWARES_df = Threat_Fox_MALWARES_df.reset_index(drop=True)

        # Add 'unknown' type to each malware
        Threat_Fox_MALWARES_df['type'] = 'unknown'

        logging.info("Finished creating the 'Malwares' ER schema for Threat Fox.")
        return Threat_Fox_MALWARES_df

    except Exception as e:
        logging.error(f"An error occurred while creating the 'Malwares' ER schema for Threat Fox: {e}")
        raise

def create_ENTRIES_Threat_Fox(df):
    """
    Drops columns and organizes the DataFrame for Threat Fox entries.

    :param df: threat fox data frame
    :return: A cleaned DataFrame of the 'Entries' ER schema for Threat Fox.
    """
    try:
        logging.info("Starting to create the 'Entries' ER schema for Threat Fox.")

        # Drop unnecessary columns and organize the DataFrame
        Threat_Fox_ENTRIES_df = df.drop(columns=['malware_alias', 'tags'])

        logging.info("Finished creating the 'Entries' ER schema for Threat Fox.")
        return Threat_Fox_ENTRIES_df

    except Exception as e:
        logging.error(f"An error occurred while creating the 'Entries' ER schema for Threat Fox: {e}")
        raise

# CLEANING OF ER SCHEMAS

def clean_ENTRIES_Threat_Fox(df):
    """
    Cleans the 'Entries' ER schema for Threat Fox.

    :param df: threat fox data frame
    """
    try:
        logging.info("Starting to clean the 'Entries' ER schema for Threat Fox.")

        # Drop the 'reference' column
        logging.info("Dropping the 'reference' column...")
        Threat_Fox_ENTRIES_df = df.drop(['reference'], axis=1)

        # Imputation Operations
        logging.info("Performing imputation operations...")
        # For 'last_seen' column, use imputation related to the 'first_seen' column
        Threat_Fox_ENTRIES_df['last_seen'].where(~(Threat_Fox_ENTRIES_df.last_seen.isnull()), other=Threat_Fox_ENTRIES_df.first_seen, inplace=True)

        # If the field 'malware_printable' is 'Unknown malware', set it to np.NaN
        Threat_Fox_ENTRIES_df['malware_printable'].where(~(Threat_Fox_ENTRIES_df.malware_printable == 'Unknown malware'), other=np.nan, inplace=True)

        # Standardization Operations
        logging.info("Performing standardization operations...")
        # Replace 'botnet_cc' with 'botnet' in the 'threat_type' field
        Threat_Fox_ENTRIES_df['threat_type'].where(~(Threat_Fox_ENTRIES_df.threat_type == 'botnet_cc'), other='botnet', inplace=True)

        # Delete UTC from 'first_seen' and 'last_seen' columns
        Threat_Fox_ENTRIES_df['first_seen'] = Threat_Fox_ENTRIES_df['first_seen'].str.replace(' UTC', '')
        Threat_Fox_ENTRIES_df['last_seen'] = Threat_Fox_ENTRIES_df['last_seen'].str.replace(' UTC', '')

        # Build the ER
        logging.info("Building the ER schema...")
        columns_ordered = ['ID_ENTRY', 'source', 'ioc', 'ioc_type', 'threat_type', 'malware', 'first_seen', 'last_seen', 'reporter', 'reference']
        Threat_Fox_ENTRIES_df = Threat_Fox_ENTRIES_df.rename(columns={"id": "ID_ENTRY", "malware_malpedia": "reference", 'malware_printable': 'malware'})
        Threat_Fox_ENTRIES_df["source"] = "Threat Fox"
        Threat_Fox_ENTRIES_df = Threat_Fox_ENTRIES_df[columns_ordered]

        # Prepare for similarity comparison
        logging.info("Preparing the 'malware' field for similarity comparison...")
        Threat_Fox_ENTRIES_df = prepare_for_similarity_comparison(Threat_Fox_ENTRIES_df, 'malware', 'malware')

        logging.info("Finished cleaning the 'Entries' ER schema for Threat Fox.")
        return Threat_Fox_ENTRIES_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Entries' ER schema for Threat Fox: {e}")
        raise

def clean_TAGS_Threat_Fox(df):
    """
    Cleans the 'Tags' ER schema for Threat Fox.

    :param df: The input DataFrame containing the tags to be cleaned.
    :return: A cleaned DataFrame of the 'Tags' ER schema for Threat Fox.
    """
    try:
        logging.info("Starting to clean the 'Tags' ER schema for Threat Fox.")

        # Drop NaNs
        logging.info("Dropping NaN values from the DataFrame...")
        Threat_Fox_TAGS_df = df.dropna().reset_index(drop=True)

        # Data Normalization
        logging.info("Normalizing the 'tag' field for similarity comparison...")
        Threat_Fox_TAGS_df = prepare_for_similarity_comparison(Threat_Fox_TAGS_df, 'tag', 'tag')

        # Drop Duplicates
        logging.info("Dropping duplicate entries from the DataFrame...")
        Threat_Fox_TAGS_df = Threat_Fox_TAGS_df.drop_duplicates().reset_index(drop=True)

        logging.info("Finished cleaning the 'Tags' ER schema for Threat Fox.")
        return Threat_Fox_TAGS_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Tags' ER schema for Threat Fox: {e}")
        raise

def clean_MALWARES_Threat_Fox(df):
    """
    Cleans the 'Malwares' ER schema for Threat Fox.

    :param df: The input DataFrame containing the malwares to be cleaned.
    :return: A cleaned DataFrame of the 'Malwares' ER schema for Threat Fox.
    """
    try:
        logging.info("Starting to clean the 'Malwares' ER schema for Threat Fox.")

        # Drop NaNs
        logging.info("Dropping NaN values from the DataFrame...")
        Threat_Fox_MALWARES_df = df.dropna().reset_index(drop=True)

        # Data Normalization
        logging.info("Normalizing the 'malware' field for similarity comparison...")
        Threat_Fox_MALWARES_df = prepare_for_similarity_comparison(Threat_Fox_MALWARES_df, 'malware', 'malware')

        # Drop Duplicates
        logging.info("Dropping duplicate entries from the DataFrame...")
        Threat_Fox_MALWARES_df = Threat_Fox_MALWARES_df.drop_duplicates().reset_index(drop=True)

        logging.info("Finished cleaning the 'Malwares' ER schema for Threat Fox.")
        return Threat_Fox_MALWARES_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Malwares' ER schema for Threat Fox: {e}")
        raise

def clean_ALIAS_Threat_Fox(df):
    """
    Cleans the 'Alias' ER schema for Threat Fox.

    :param df: The input DataFrame containing the aliases to be cleaned.
    :return: A cleaned DataFrame of the 'Alias' ER schema for Threat Fox.
    """

    try:
        logging.info("Starting to clean the 'Alias' ER schema for Threat Fox.")

        # Drop NaNs
        logging.info("Dropping NaN values from the DataFrame...")
        Threat_Fox_ALIAS_df = df.dropna().reset_index(drop=True)

        # Data Normalization
        logging.info("Normalizing the 'alias' field for similarity comparison...")
        Threat_Fox_ALIAS_df = prepare_for_similarity_comparison(Threat_Fox_ALIAS_df, 'malware', 'malware')
        Threat_Fox_ALIAS_df = prepare_for_similarity_comparison(Threat_Fox_ALIAS_df, 'alias', 'alias')

        # Drop Duplicates
        logging.info("Dropping duplicate entries from the DataFrame...")
        Threat_Fox_ALIAS_df = Threat_Fox_ALIAS_df.drop_duplicates().reset_index(drop=True)

        logging.info("Finished cleaning the 'Alias' ER schema for Threat Fox.")
        return Threat_Fox_ALIAS_df

    except Exception as e:
        logging.error(f"An error occurred while cleaning the 'Alias' ER schema for Threat Fox: {e}")
        raise

