"""
Data collection

Leonardo Cesani, 18-11-2024
"""

# Libraries
import logging
import pandas as pd
import urllib3
import json
import requests
from io import StringIO
from Utils.data_utils import APIKeys, DataSourcesPaths, save_csv

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

def submit_ioc_to_threatfox(source, auth_key, day):
    """
    Submit IOCs to ThreatFox API.

    Parameters:
    - source (str): The ThreatFox API source URL.
    - auth_key (str): Your ThreatFox API authentication key.
    - day (int): Number of days to retrieve data for.

    Returns:
    - dict: Response from the ThreatFox API.
    """
    # Prepare HTTPSConnectionPool with certificate verification
    headers = {
        "Auth-Key": auth_key,
    }
    pool = urllib3.HTTPSConnectionPool(
        source,
        port=443,
        maxsize=10000,
        headers=headers,
        cert_reqs='CERT_NONE'
    )
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # Prepare the data payload
    data = {
        'query': 'get_iocs',
        'days': day
    }

    # Convert data to JSON and send the request
    json_data = json.dumps(data)
    response = pool.request("POST", "/api/v1/", body=json_data)

    # Decode the response
    response_data = response.data.decode("utf-8", "ignore")
    return json.loads(response_data)

class DataCollection:
    def __init__(self):
        # API keys
        self.threat_fox_key = APIKeys.THREAT_FOX

        # URLs
        self.threat_fox_url = "threatfox-api.abuse.ch"
        self.url_haus_url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
        self.feodo_tracker_url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'

        # Save Paths
        self.threat_fox_save_path = DataSourcesPaths.THREAT_FOX
        self.url_haus_save_path = DataSourcesPaths.URL_HAUS
        self.feodo_tracker_save_path = DataSourcesPaths.FEODO_TRACKER

    def get_threat_fox_data(self, day: int = 7):
        """
        Get the Threat Fox data from the API and save it as a DataFrame.

        :param day: Number of days to retrieve data for. Default is 7 days.
        :return: DataFrame containing the Threat Fox data.
        """
        try:
            # Set up API key and payload
            logging.info(f"Requesting Threat Fox data...")

            # Define payload for the request
            response_data = submit_ioc_to_threatfox(
                source=self.threat_fox_url,
                auth_key=self.threat_fox_key,
                day=day
            )

            # Extract and normalize 'data' field into a DataFrame
            if 'data' in response_data and response_data['data']:
                df = pd.json_normalize(response_data['data'])
            else:
                logging.warning(f"No data found in the Threat Fox response.")
                df = pd.DataFrame()  # Return an empty DataFrame if 'data' key is missing or empty

            # Save the data
            dataframes_dict = {'Threat_Fox': df}
            save_csv(dataframes_dict, self.threat_fox_save_path)
            logging.info(f"Threat Fox data saved successfully.")

        except urllib3.exceptions.HTTPError as e:
            logging.error(f"HTTP error occurred while fetching Threat Fox data: {e}")
        except json.JSONDecodeError:
            logging.error(f"Failed to parse JSON response from Threat Fox API.")
        except Exception as e:
            logging.error(f"An error occurred while processing Threat Fox data: {e}")

    def get_url_haus_data(self):
        """
        Get the URL Haus data from the API and save it as a DataFrame.

        :return: DataFrame containing the URL Haus data.
        """
        try:
            logging.info( f"Requesting URL Haus data...")
            # Use a requests session to get the data
            with requests.Session() as s:
                response = s.get(self.url_haus_url)

                # Check for successful response
                if response.status_code != 200:
                    raise Exception(f"Failed to get data from URL Haus API. Status code: {response.status_code}")

                # Convert the response content to a pandas DataFrame
                df = pd.read_csv(StringIO(response.text), header=8, on_bad_lines='skip')

            # Save the data
            dataframe_dict = {'URL_Haus': df}
            save_csv(dataframe_dict, self.url_haus_save_path)
            logging.info( f"URL Haus data saved successfully.")

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error occurred while fetching URL Haus data: {e}")
        except pd.errors.ParserError:
            logging.error( f"Failed to parse CSV response from URL Haus API.")
        except Exception as e:
            logging.error(f"An error occurred while processing URL Haus data: {e}")

    def get_feodo_tracker_data(self):
        """
        Get the Feodo Tracker data from the API and save it as a DataFrame.

        :return: DataFrame containing the Feodo Tracker data.
        """
        try:
            logging.info( f"Requesting Feodo Tracker data...")
            # Use a requests session to get the data
            with requests.Session() as s:
                response = s.get(self.feodo_tracker_url)

                # Check for successful response
                if response.status_code != 200:
                    raise Exception(f"Failed to get data from Feodo Tracker API. Status code: {response.status_code}")

                # Decode the content and load it as JSON
                decoded_content = response.content.decode('utf-8', 'ignore')

                try:
                    data = json.loads(decoded_content)
                except json.JSONDecodeError:
                    raise Exception( f"Failed to parse JSON response from Feodo Tracker API.")

                # Normalize the JSON data into a pandas DataFrame
                df = pd.json_normalize(data)

            # Save the data
            dataframe_dict = {'Feodo_Tracker': df}
            save_csv(dataframe_dict, self.feodo_tracker_save_path)
            logging.info( f"Feodo Tracker data saved successfully.")

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error occurred while fetching Feodo Tracker data: {e}")
        except json.JSONDecodeError:
            logging.error( f"Failed to parse JSON response from Feodo Tracker API.")
        except Exception as e:
            logging.error(f"An error occurred while processing Feodo Tracker data: {e}")


def collect_data():
    data_collector = DataCollection()

    try:
        logging.info( f"Starting data collection...")
        data_collector.get_threat_fox_data()
        data_collector.get_url_haus_data()
        # data_collector.get_feodo_tracker_data()
        logging.info( f"Data collection completed successfully.")
    except Exception as e:
        logging.error(f"An error occurred during the data collection process: {e}")


if __name__ == "__main__":
    collect_data()

