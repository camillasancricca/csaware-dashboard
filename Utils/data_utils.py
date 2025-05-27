"""
Path to data sources, saving functions

Leonardo Cesani, 16-11-2024
"""

# Libraries
import pandas as pd
import logging
import os
import errno
import math

# CONSTANTS
class DataSource:
   FEODO_TRACKER = "Feodo_Tracker"
   THREAT_FOX = "Threat_Fox"
   URL_HAUS = "URL_Haus"

class DataSourcesPaths:
   DATA_SOURCE = "./Data/NewData/"
   FEODO_TRACKER = DATA_SOURCE + DataSource.FEODO_TRACKER + "/"
   THREAT_FOX  = DATA_SOURCE + DataSource.THREAT_FOX + "/"
   URL_HAUS = DATA_SOURCE + DataSource.URL_HAUS + "/"

class DataERPath:
   SAVE_PATH = "./Data/NewData/"
   FEODO_TRACKER_ER_PATH =SAVE_PATH + DataSource.FEODO_TRACKER + "/"
   THREAT_FOX_ER_PATH = SAVE_PATH + DataSource.THREAT_FOX + "/"
   URL_HAUS_ER_PATH = SAVE_PATH + DataSource.URL_HAUS + "/"

class FinalDataERPath:
    SAVE_PATH = "./Data/"
    DATA_PATH = SAVE_PATH + "Data.csv"

class APIKeys:
   """
   API keys for Threat Fox. Replace 'YOUR_API_KEY' with your own API key.
   """
   THREAT_FOX = "5b1e2eb06e18050f65ac6d532c99db9903fab3e1b89e4eaa"

class StreamlitConfig:
    CONFIG_PATH = "./Streamlit/streamlit_config.json"

class ERSchemas:
   ALIAS = 'Alias'
   ENTRIES = 'Entries'
   MALWARES = 'Malwares'
   TAGS = 'Tags'
   CITIES = 'Cities'
   COUNTRIES = 'Countries'
   IP_ADDRESSES = 'IP_Addresses'

class ImagePath:
    IMAGE_PATH = "./Images/"
    LOGO_PATH = IMAGE_PATH + "CS_AWARE_NEXT_logo.png"
    TAB_LOGO_PATH = IMAGE_PATH + "CS_AWARE_NEXT_tab_logo.png"

class ClassesLogs:
    CLASSES_PATH = "./Utils/Logs/maps_classes.json"

class LogsData:
    LOGS_PATH = "./Data/Logs/"

class PostsData:
    POSTS_PATH = "./Data/Posts/"

    import requests

    class PostsAuth:
        ACCESS_TOKEN = ""
        ID_TOKEN = ""

def fetch_auth_token():
    url = f"http://52.48.88.83:8000/auth/token?email=camilla.sancricca%40polimi.it&password=Camillacsaware97%21"
    headers = {
        "accept": "application/json"
    }

    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()  # Raise an error for HTTP errors
        data = response.json()

        # Update the PostsAuth class variables
        PostsAuth.ACCESS_TOKEN = data.get("access_token", "")
        PostsAuth.ID_TOKEN = data.get("id_token", "")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching auth token: {e}")


class PostsAuth:
        ACCESS_TOKEN =  "eyJraWQiOiJ4VXNkQnY3U3VyRHE4bUJkd3llZDRtdWdSa3ZtT1Arb1pBMlFLVXEzVmFvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhMjk1MzQyNC04MDgxLTcwODYtYzVmMC1lOWFmYWJlNzI4YjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMV82NFo0T3JBSmkiLCJjbGllbnRfaWQiOiI3cWJka3RvbTFjNjhtcm1wc2JwYTVzZ2doNCIsIm9yaWdpbl9qdGkiOiJlYjcwNzg5Yi04YWMwLTQ3MDQtYTI5OS05MTUyMTk0YzQzYzAiLCJldmVudF9pZCI6ImI2ODM1MzQ5LWI3NmUtNDJmOC1hNzNjLTQwNWRiZTFjMjg4OCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE3MzkxOTkzMzcsImV4cCI6MTczOTI4NTczNywiaWF0IjoxNzM5MTk5MzM3LCJqdGkiOiI2ODg3YjNkYi1iMGQ2LTQ5YzktYTE0Mi00NjRkZWZkNDQ0ZDgiLCJ1c2VybmFtZSI6ImNhbWlsbGEifQ.ORQXcRghS7PY0yIVzipMQgTSAeozc0Mvei_m8bZ30yWYqRVQVRxFY-ZoRAeRvRxFvRhQ1gLAAms-raNWd6HXkP3N7iJFu3HFCwXVLgFVA60oV2Z25tSUqkPu5g_d08jSJgULyny0Sg88eM6SqmRPKPeqhzPkWcctPWcBsizzskiTjHkMpQpAG80KoPqKqHD9LJguq5o0xSe_nD4FQEGvMUh20a86rFF86psYq3VgHOMFIiwGzEi05XkclG23CRlZbXpCByXFOkdV26kyXKVmWeUNf53W-HM6UpGV82f1s9HSAwSRuJAOdMbtkKAe1G4pF7jBL2D7Z1lw7qZTHrSqRQ"
        ID_TOKEN = "eyJraWQiOiJhTHZsTHdubW1NNk1vTkhKcCtwRkRONUJ4MUoxNXNsalpnSGVDNTNJTHpRPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhMjk1MzQyNC04MDgxLTcwODYtYzVmMC1lOWFmYWJlNzI4YjMiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicHJvZmlsZSI6ImFkbWluIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMS5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTFfNjRaNE9yQUppIiwiY29nbml0bzp1c2VybmFtZSI6ImNhbWlsbGEiLCJvcmlnaW5fanRpIjoiZWI3MDc4OWItOGFjMC00NzA0LWEyOTktOTE1MjE5NGM0M2MwIiwiYXVkIjoiN3FiZGt0b20xYzY4bXJtcHNicGE1c2dnaDQiLCJldmVudF9pZCI6ImI2ODM1MzQ5LWI3NmUtNDJmOC1hNzNjLTQwNWRiZTFjMjg4OCIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNzM5MTk5MzM3LCJuYW1lIjoiY2FtaWxsYSIsImV4cCI6MTczOTI4NTczNywiaWF0IjoxNzM5MTk5MzM3LCJqdGkiOiI3ZGQyZDFkZC04YTY3LTQ3ZmQtYmFiZC00YjJmMTFkNTZhMGEiLCJlbWFpbCI6ImNhbWlsbGEuc2FuY3JpY2NhQHBvbGltaS5pdCJ9.MkENtGgRW-7Xlw0CdEGCAD2lkSAUvA5kpz401CVYlKhi3Q3v7ZzJeQO8OFE9jIO8v1kyf5SeyeBszG5_mqcJJHRdfgj8HEMx5qeaeiQ68wKGgBTTy9ekVqBH_iBomFzQePL1cISKugUFRhykHj-BzsFaiFzJa-FwPpd4sWl6UIR5PHdTQrsOt23kfVYVJ0dI7xmiWDm-HsJzOXPrLhfwmSRQ8gjdLvVa2Eqpy3vtMtS31oL5z17doELqO2GcF6QGH9bQGarT5OntTbfM8wcV0iOIL2qoLlknmdZyZx1fl1FUdTMrp4IH9bEeIvX3klYL-JOqnfOwKsP5cgRSihoJtA"


# SAVING FUNCTIONS

def check_directory_and_create(dir_name: str = None) -> None:
    """
    Checks if a directory exists, and creates it if it does not.

    :param dir_name: The name of the directory to check and create if necessary.
    """
    directory_path =  None
    try:
        directory_path = os.path.dirname(dir_name + "/")
        if not os.path.exists(directory_path):
            logging.info(f"Directory does not exist, creating: {directory_path}")
            os.makedirs(directory_path)
            logging.info(f"Directory created successfully: {directory_path}")
        else:
            logging.info(f"Directory already exists: {directory_path}")
    except OSError as exc:  # Guard against race condition
        if exc.errno != errno.EEXIST:
            logging.error(f"Failed to create directory {directory_path}. Error: {exc}")
            raise

def save_csv(dataframes_dict: dict = None, save_directory: str = None):
    """
    Saves each DataFrame in the provided dictionary to the specified directory as a CSV file.

    :param dataframes_dict: A dictionary where keys are filenames (without extensions) and values are pandas DataFrames.
    :param save_directory: The directory where the CSV files will be saved.
    """
    try:
        # Ensure save directory exists
        logging.info(f"Checking if save directory exists: {save_directory}")
        check_directory_and_create(save_directory)

        # Iterate through dataframes and save each as a CSV file
        for key, df in dataframes_dict.items():
            file_name = f"{key}.csv"
            file_path = os.path.join(save_directory, file_name)
            logging.info(f"Saving DataFrame to: {file_path}")
            df.to_csv(file_path, index=False)
            logging.info(f"DataFrame saved successfully: {file_path}")

    except Exception as e:
        logging.error(f"An error occurred while saving CSV files to {save_directory}. Error: {e}")

def append_to_csv(dataframes_dict: dict = None, save_directory: str = None):
    """
    Appends new data to an existing CSV file in the specified directory.

    :param dataframes_dict: A dictionary where keys are filenames (without extensions) and values are pandas DataFrames.
    :param save_directory: The directory where the CSV files are stored.
    """
    try:
        # Ensure save directory exists
        logging.info(f"Checking if save directory exists: {save_directory}")
        check_directory_and_create(save_directory)

        for key, new_df in dataframes_dict.items():
            file_path = os.path.join(save_directory, f"{key}.csv")

            if os.path.exists(file_path):
                logging.info(f"File {file_path} exists. Reading existing data.")
                # Load the existing data
                existing_df = pd.read_csv(file_path)

                # Identify new columns in new_df that are not in existing_df
                new_columns = set(new_df.columns) - set(existing_df.columns)
                for col in new_columns:
                    # Add missing columns to existing_df with default values
                    logging.info(f"Adding missing column {col} to existing data.")
                    existing_df[col] = None

                # Ensure new_df has the same columns as existing_df
                for col in set(existing_df.columns) - set(new_df.columns):
                    # Add missing columns to new_df with default values
                    logging.info(f"Adding missing column {col} to new data.")
                    new_df[col] = None

                # Ensure column order matches
                new_df = new_df[existing_df.columns]

                # Append the new data to the existing data
                combined_df = pd.concat([existing_df, new_df], ignore_index=True)
            else:
                logging.info(f"File {file_path} does not exist. Creating new file.")
                # If the file doesn't exist, treat the new DataFrame as the combined DataFrame
                combined_df = new_df

            # Save the combined data back to the CSV file
            logging.info(f"Saving combined DataFrame to: {file_path}")
            combined_df.to_csv(file_path, index=False)
            logging.info(f"DataFrame saved successfully: {file_path}")

    except Exception as e:
        logging.error(f"An error occurred while appending data to CSV files in {save_directory}. Error: {e}")


# OPERATIONAL FUNCTIONS

def prepare_for_similarity_comparison(df, col_i, col_f):
    """
    Prepares a column of the DataFrame for similarity comparison by normalizing text values.

    This function processes the text in the specified column, converting it to lowercase, adding spaces at the start
    and end, and removing various special characters.

    :param df: The input DataFrame containing the data to be processed.
    :param col_i: The name of the column to be processed.
    :param col_f: The name of the output column where the processed text will be stored.
    :return: A DataFrame with the processed column for similarity comparison.
    """
    try:
        logging.info(f"Starting the preparation for similarity comparison for column: {col_i}")

        for i in range(len(df)):
            value = df.at[i, col_i]

            # Only process non-null and non-NaN values
            if not isinstance(value, float) or not math.isnan(value):
                value = ' ' + value + ' '
                value = value.lower()
                value = value.replace('?', ' ').replace('!', ' ').replace('%', ' ').replace('.', ' ').replace('-', ' ')
                value = value.replace('[', ' ').replace(']', ' ').replace('(', ' ').replace(')', ' ')
                value = value.replace('\\', ' ').replace(',', ' ').replace('_', ' ')
                value = value.strip()

            # Set the processed value to the output column
            df.loc[i, col_f] = value

        logging.info(f"Finished preparing column: {col_i} for similarity comparison.")
        return df

    except Exception as e:
        logging.error(f"An error occurred while preparing the DataFrame for similarity comparison: {e}")
        raise

# GEOLOCATION FUNCTIONS
import requests
import pandas as pd
import time

def get_geolocation_ip_api(ip_address):
    """
    Gets geolocation information for a given IP address using ip-api service.

    :param ip_address: The IP address to geolocate.
    :return: A dictionary with geolocation information (country, region, city, etc.), or None if there was an error.
    """
    url = f"http://ip-api.com/json/{ip_address}"

    try:
        # Make the request to the ip-api service
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            data = response.json()

            if data['status'] == 'fail':
                logging.error(f"Failed to retrieve data for IP: {ip_address}")
                return None

            return {
                'ip_address': ip_address,
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city')
            }
        else:
            logging.error(f"Failed to retrieve data for IP: {ip_address}. HTTP Error Code: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        return None

def get_top_k_geolocation(df, top_k=5):
    """
    Get geolocation for the IPs related to the top-k malwares.

    :param df: The DataFrame containing 'malware' and 'ip_address' columns.
    :param top_k: The number of top malwares to consider.
    :return: A DataFrame containing geolocation data for the top-k malwares' associated IPs.
    """
    # Step 1: Identify the top-k malwares by frequency
    top_malwares = df['malware'].value_counts().nlargest(top_k).index

    # Step 2: Filter the data for these top-k malwares
    df_top_k_malwares = df[df['malware'].isin(top_malwares)]

    # Step 3: Get unique IPs related to the top-k malwares
    ip_addresses = df_top_k_malwares['ip_address'].unique()

    # Step 4: Keep track of already processed IPs
    processed_ips = set()

    logging.info(f"Processing {len(ip_addresses)} unique IP addresses for geolocation data...")

    # Step 5: Get geolocation data for each IP
    geo_data = []
    for ip in ip_addresses:
        if pd.isna(ip) or ip in processed_ips:  # Skip NaN IPs or already processed IPs
            continue

        geo_info = get_geolocation_ip_api(ip)
        if geo_info:
            geo_data.append(geo_info)
            processed_ips.add(ip)  # Mark this IP as processed

        # Step 6: Add a delay to avoid hitting the API rate limit
        time.sleep(1)  # Sleep for 1 second between requests to avoid too many requests

    # Step 7: Convert the geo data to a DataFrame
    geo_df = pd.DataFrame(geo_data)

    return geo_df