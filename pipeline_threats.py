"""
Implementation of the complete pipeline for the threat detection.

Leonardo Cesani, 4-12-2024
"""

# Libraries
import pandas as pd
import logging

from Scripts.Threats.data_collection import collect_data
from Scripts.Threats.ER_schema_creation import create_ER_schemas
from Scripts.Threats.data_cleaning import clean_sources_ER_schemas
from Scripts.Threats.data_integration import integrate_ER_schemas
from Scripts.Threats.data_profiling import profile_ER_schema
from Scripts.Threats.data_enrichment import enrich
from Utils.data_utils import append_to_csv, DataERPath, ERSchemas, FinalDataERPath, get_top_k_geolocation

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

def main():
    collect_data()
    create_ER_schemas()
    clean_sources_ER_schemas()
    integrate_ER_schemas()
    enrich()
    profile_ER_schema()

    # Read the CSV files into DataFrames
    entries_df =  pd.read_csv(DataERPath.SAVE_PATH + ERSchemas.ENTRIES + ".csv")
    tags_df = pd.read_csv(DataERPath.SAVE_PATH + ERSchemas.TAGS + ".csv")
    alias_df =  pd.read_csv(DataERPath.SAVE_PATH + ERSchemas.ALIAS + ".csv")
    malwares_df =  pd.read_csv(DataERPath.SAVE_PATH + ERSchemas.MALWARES + ".csv")

    geo_df = get_top_k_geolocation(entries_df, top_k=5)
    entries_df = entries_df.merge(geo_df, on='ip_address', how='left')

    # Save the single dataframes
    data_dictionary = {
        'Entries': entries_df,
        'Tags': tags_df,
        'Alias': alias_df,
        'Malwares':malwares_df,
    }

    # Now call the append_to_csv function with the DataFrames
    # append_to_csv(data_dictionary, FinalDataERPath.SAVE_PATH)

    # Perform the joins
    entries_df = entries_df.merge(alias_df, on='malware', how='left')
    entries_df = entries_df.merge(tags_df, on=['ID_ENTRY', 'source'], how='left')
    entries_df = entries_df.drop_duplicates()


    # Save the final dataframe
    final_data={
        'Data': entries_df
    }

    # append_to_csv(final_data, FinalDataERPath.SAVE_PATH)


if  __name__ == "__main__":
    main()