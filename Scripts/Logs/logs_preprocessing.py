"""
Preprocessing of logs

Leo: 08-01-2025
"""

# Libraries
import os
import re
import datetime
from datetime import timedelta
import json
import pandas as pd
import logging
import warnings

from Utils.data_utils import ClassesLogs, LogsData, save_csv

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

# Filter warnings
warnings.simplefilter(action='ignore', category=pd.errors.PerformanceWarning)

# Functions definitions
def get_classes_json():
    """
    Get the classes from the JSON file
    :return: classes
    """
    try:
        with open(ClassesLogs.CLASSES_PATH, "r") as file:
            classes = json.load(file)
            logging.info("Successfully loaded classes from JSON file.")
            return classes
    except FileNotFoundError as e:
        logging.error(f"Classes JSON file not found: {e}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from classes file: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error while reading classes JSON file: {e}")
        raise

def create_type_table():
    """
    Create the type table
    :return: type table
    """
    try:
        classes = get_classes_json()
        logging.info("Successfully retrieved classes for type table.")

        type_data = classes["type"]
        type_id = list(range(len(type_data)))

        type_table = {
            'type_id': type_id,
            'type': type_data
        }

        type_df = pd.DataFrame(type_table)
        logging.info("Type table DataFrame created successfully.")

        dataframe_dict = {
            'Type': type_df
        }

        save_csv(dataframe_dict, LogsData.LOGS_PATH)
        logging.info("Type table saved to CSV successfully.")

        return type_df

    except KeyError as e:
        logging.error(f"Missing key in classes JSON: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"Error saving type table CSV: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in create_type_table: {e}")
        raise

def create_event_types_table():
    """
    Create the event types table
    :return: event types table
    """
    try:
        classes = get_classes_json()
        logging.info("Successfully retrieved classes for event types table.")

        event_types = classes["event_types"]
        detailed_event_types = event_types.copy()

        detailed_id_map = classes["detailed_id_map"]
        for key, value in detailed_id_map.items():
            new_class = value
            if new_class not in detailed_event_types:
                detailed_event_types.append(new_class)

        suricata_alerts_classes = classes["suricata_alerts_classes"]
        for key, value in suricata_alerts_classes.items():
            new_class = "suricata." + key
            if new_class not in detailed_event_types:
                detailed_event_types.append(new_class)

        event_type_id = list(range(len(detailed_event_types)))
        event_types_table = {
            'event_type_id': event_type_id,
            'event_type': detailed_event_types
        }

        event_types_df = pd.DataFrame(event_types_table)
        logging.info("Event types table DataFrame created successfully.")

        dataframe_dict = {
            'EventTypes': event_types_df
        }

        save_csv(dataframe_dict, LogsData.LOGS_PATH)
        logging.info("Event types table saved to CSV successfully.")

        return event_types_df

    except KeyError as e:
        logging.error(f"Missing key in classes JSON: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"Error saving event types table CSV: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in create_event_types_table: {e}")
        raise

def zeek_process_line(logline, facility, type_df, event_type_df, date, time, event, ip_address):
    try:
        if isinstance(logline['ts'], float):
            try:
                d = datetime.datetime.fromtimestamp(int(str(logline['ts'])[:10]))
                d = d - timedelta(hours=2)

                facility = re.sub(r"\.logs$", '', facility)
                facility = re.sub(r"_", '.', facility)

                e_type = event_type_df[event_type_df['event_type'] == facility]

                if not e_type.empty:
                    type_id = e_type['event_type_id'].item()
                else:
                    other = event_type_df[event_type_df['event_type'] == 'zeek.other']
                    type_id = other['event_type_id'].item()

                event['event_type_id'].append(type_id)

                date['date'].append(d.date())
                date['year'].append(d.year)
                date['month'].append(d.month)
                date['day_of_week'].append(d.weekday())
                date['day'].append(d.day)

                time['time'].append(d.time())
                time['hour'].append(d.hour)
                time['minute'].append(d.minute)
                time['second'].append(d.second)

                row_type = type_df[type_df['type'] == 'zeek']
                type_id = row_type['type_id'].item()
                event['type_id'].append(type_id)

                event['date'].append(d.date())
                event['time'].append(d.time())

                if facility == 'zeek_dns.logs':
                    ip = logline.get('orig_h', '')
                elif facility == 'zeek_dhcp.logs':
                    ip = logline.get('client_addr', '')
                elif facility == 'zeek.logs':
                    match = re.search(r"srcip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", logline.get('message', ''))
                    if match:
                        ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", match.group()).group()
                    else:
                        ip = ''
                else:
                    ip = logline.get('id.orig_h', '')

                if ip and ip != '-' and ip not in ip_address['ip_address']:
                    ip_address['ip_address'].append(ip)
                    new_ip_id = len(ip_address['ip_address_id']) + 1
                    ip_address['ip_address_id'].append(new_ip_id)
                    event['ip_address_id'].append(new_ip_id)
                elif ip:
                    index = ip_address['ip_address'].index(ip) + 1
                    event['ip_address_id'].append(index)
                else:
                    event['ip_address_id'].append(1)

            except Exception as e:
                logging.error(f"Error processing timestamp or facility: {e}")
                raise
        else:
            logging.warning("Skipping logline: 'ts' is not a float.")

    except KeyError as e:
        logging.error(f"Missing key in logline: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in zeek_process_line: {e}")
        raise

def windows_process_line(logline, type_df, event_type_df, date, time, event, ip_address):
    try:
        # Parse the timestamp
        t = datetime.datetime.strptime(logline["TimeCreated"][:19], '%Y/%m/%d %H:%M:%S')

        # Add date components
        date['date'].append(t.date())
        date['year'].append(t.year)
        date['month'].append(t.month)
        date['day_of_week'].append(t.weekday())
        date['day'].append(t.day)

        # Add time components
        time['time'].append(t.time())
        time['hour'].append(t.hour)
        time['minute'].append(t.minute)
        time['second'].append(t.second)

        # Add event ID
        if len(event['id']) == 0:
            event['id'].append(1)
        else:
            event['id'].append(len(event['id']) + 1)

        event['date'].append(t.date())
        event['time'].append(t.time())

        # Process type
        row_type = type_df[type_df['type'] == 'windows']
        if row_type.empty:
            logging.error("No type_id found for 'windows' in type_df.")
            raise KeyError("Missing 'type_id' for 'windows' in type_df.")
        type_id = row_type['type_id'].item()
        event['type_id'].append(type_id)

        # Get event type from classes
        classes = get_classes_json()
        detailed_id_map = classes["detailed_id_map"]

        e_type = detailed_id_map.get(logline['EventID'], "windows.other_non_audit_event")

        # Process event type
        row_eventType = event_type_df[event_type_df['event_type'] == e_type]
        if row_eventType.empty:
            logging.error(f"No event_type_id found for event_type: {e_type}.")
            raise KeyError(f"Missing 'event_type_id' for event_type: {e_type}.")
        type_id = row_eventType['event_type_id'].item()
        event['event_type_id'].append(type_id)

        # Extract IP address
        match = re.search(r'Source Network Address:\td{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', logline['Description'])

        if match:
            match_ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', match.group())
            ip = match_ip.group() if match_ip else ''
        else:
            ip = ''

        # Add IP address to the event
        if ip:
            if ip not in ip_address['ip_address']:
                ip_address['ip_address'].append(ip)
                new_ip_id = len(ip_address['ip_address_id']) + 1
                ip_address['ip_address_id'].append(new_ip_id)
                event['ip_address_id'].append(new_ip_id)
            else:
                index = ip_address['ip_address'].index(ip) + 1
                event['ip_address_id'].append(index)
        else:
            event['ip_address_id'].append(1)

    except KeyError as e:
        logging.error(f"Missing key in logline: {e}")
        raise
    except ValueError as e:
        logging.error(f"Error parsing date or description: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in windows_process_line: {e}")
        raise

def syslog_process_line(timestamp, logline, type_df, event_type_df, date, time, event, ip_address):
    try:
        # Parse the timestamp
        t = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S%z')

        # Extract IP address from the log message
        ip_match = re.search(r'IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', logline['message'])
        ip = ip_match.group(1) if ip_match else ''

        # Add IP address to the ip_address table and link to the event
        if ip:
            if ip not in ip_address['ip_address']:
                new_ip_id = len(ip_address['ip_address']) + 1
                ip_address['ip_address'].append(ip)
                ip_address['ip_address_id'].append(new_ip_id)
                ip_address['date'].append(t.date())

    except KeyError as e:
        logging.error(f"Missing key in logline: {e}")
        raise
    except ValueError as e:
        logging.error(f"Error parsing date or description: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in syslog_process_line: {e}")
        raise

def suricata_eve_process_line(logline, type_df, event_type_df, date, time, event, ip_address):
    try:
        t = datetime.datetime.strptime(logline["timestamp"][:19], '%Y-%m-%dT%H:%M:%S')

        date['date'].append(t.date())
        date['year'].append(t.year)
        date['month'].append(t.month)
        date['day_of_week'].append(t.weekday())
        date['day'].append(t.day)

        time['time'].append(t.time())
        time['hour'].append(t.hour)
        time['minute'].append(t.minute)
        time['second'].append(t.second)

        event['date'].append(t.date())
        event['time'].append(t.time())

        if len(event['id']) == 0:
            event['id'].append(1)
        else:
            event['id'].append(len(event['id']) + 1)

        ip = logline.get('src_ip', '')

        if ip:
            if ip not in ip_address['ip_address']:
                ip_address['ip_address'].append(ip)
                new_ip_id = len(ip_address['ip_address_id']) + 1
                ip_address['ip_address_id'].append(new_ip_id)
                event['ip_address_id'].append(new_ip_id)
            else:
                id_ip = ip_address['ip_address'].index(ip) + 1
                event['ip_address_id'].append(id_ip)
        else:
            event['ip_address_id'].append(1)

        row_type = type_df[type_df['type'] == 'suricata.eve']
        type_id = row_type['type_id'].item()
        event['type_id'].append(type_id)

        e_type = event_type_df[event_type_df['event_type'] == "suricata." + logline['event_type']]
        if not e_type.empty:
            type_id = e_type['event_type_id'].item()
        else:
            type_id = 14

        event['event_type_id'].append(type_id)

    except KeyError as e:
        logging.error(f"Missing key in logline: {e}")
        raise
    except ValueError as e:
        logging.error(f"Error parsing timestamp or accessing DataFrame: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in suricata_eve_process_line: {e}")
        raise

def suricata_alerts_process_line(logline, type_df, event_type_df, date, time, event, ip_address):
    try:
        message = logline["message"]

        time_match = re.search(r'\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{6}', message)
        if not time_match:
            logging.error("Timestamp not found in message.")
            raise ValueError("Timestamp not found in message.")

        t = time_match.group()
        t = datetime.datetime.strptime(t[:19], '%m/%d/%Y-%H:%M:%S')

        date['date'].append(t.date())
        date['year'].append(t.year)
        date['month'].append(t.month)
        date['day_of_week'].append(t.weekday())
        date['day'].append(t.day)

        time['time'].append(t.time())
        time['hour'].append(t.hour)
        time['minute'].append(t.minute)
        time['second'].append(t.second)

        event['date'].append(t.date())
        event['time'].append(t.time())

        if len(event['id']) == 0:
            event['id'].append(1)
        else:
            event['id'].append(len(event['id']) + 1)

        row_type = type_df[type_df['type'] == 'suricata.alerts']
        event['type_id'].append(row_type['type_id'].item())

        classification_match = re.search(r'\[Classification: [^\]]+\]', message)
        if not classification_match:
            logging.error("Classification not found in message.")
            raise ValueError("Classification not found in message.")

        classification = classification_match.group()
        classification = classification.split(': ')[1].strip(']')

        classes = get_classes_json()
        suricata_alerts_classes = classes["suricata_alerts_classes"]

        e_type = "suricata.other"
        for key, desc in suricata_alerts_classes.items():
            if desc == classification:
                e_type = "suricata." + key
                break

        row_eventType = event_type_df[event_type_df['event_type'] == e_type]
        if not row_eventType.empty:
            event['event_type_id'].append(row_eventType['event_type_id'].item())
        else:
            logging.warning("Event type not found for classification, defaulting to 'suricata.other'.")
            event['event_type_id'].append(14)

        match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', logline['message'])
        if match:
            ip = match.group()
            if ip not in ip_address['ip_address']:
                ip_address['ip_address'].append(ip)
                new_ip_id = len(ip_address['ip_address_id']) + 1
                ip_address['ip_address_id'].append(new_ip_id)
                event['ip_address_id'].append(new_ip_id)
            else:
                id_ip = ip_address['ip_address'].index(ip) + 1
                event['ip_address_id'].append(id_ip)
        else:
            event['ip_address_id'].append(1)

    except KeyError as e:
        logging.error(f"Missing key in logline: {e}")
        raise
    except ValueError as e:
        logging.error(f"Error parsing message or timestamp: {e}")
        raise
    except Exception as e:
        logging.critical(f"Unexpected error in suricata_alerts_process_line: {e}")
        raise

def logs_preprocessing(dir: str = None):
    try:
        date = {
            'date': [],
            'year': [],
            'month': [],
            'day_of_week': [],
            'day': []
        }

        time = {
            'time': [],
            'hour': [],
            'minute': [],
            'second': []
        }

        event = {
            'id': [],
            'type_id': [],
            'event_type_id': [],
            'date': [],
            'time': [],
            'ip_address_id': [],
        }

        ip_address = {
            'ip_address_id': [1],
            'date': ['None'],
            'ip_address': ['None']
        }

        type_df = create_type_table()
        event_type_df = create_event_types_table()

        rootdirectory = dir

        for root, dirs, files in os.walk(rootdirectory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'r', encoding="utf8", errors='replace') as f:
                        dataset = f.readlines()
                        for i, line in enumerate(dataset):
                            if not line.strip():
                                logging.warning(f"Skipping empty line {i + 1} in file {file_name}")
                                continue

                            parts = line.split('\t', 2)

                            if len(parts) < 3:
                                logging.warning(f"Skipping malformed line {i + 1} in file {file_name}")
                                continue

                            timestamp, facility, remaining = parts

                            if '\t' in remaining:
                                message_json = remaining.split('\t', 1)[1]
                            else:
                                message_json = re.split(r'\s{2,}', remaining, maxsplit=1)[-1]

                            try:
                                logline = json.loads(message_json)

                                if re.search(r".syslog.", facility):
                                    syslog_process_line(timestamp, logline, type_df, event_type_df, date, time, event, ip_address)

                                elif re.search(r".*\.windows$", facility):
                                    windows_process_line(logline, type_df, event_type_df, date, time, event, ip_address)

                                elif re.search(r"suricata_eve.logs", facility):
                                    suricata_eve_process_line(logline, type_df, event_type_df, date, time, event, ip_address)

                                elif re.search(r"suricata_alerts.logs", facility):
                                    suricata_alerts_process_line(logline, type_df, event_type_df, date, time, event, ip_address)

                                elif re.search(r"^zeek_.*", facility):
                                    zeek_process_line(logline, facility, type_df, event_type_df, date, time, event, ip_address)

                            except json.JSONDecodeError as e:
                                logging.error(f"JSON decoding error at line {i + 1} in file {file_name}: {e}")
                                continue

                except Exception as e:
                    logging.error(f"Error processing file {file_name}: {e}")

        # Log dictionary lengths
        logging.info(f"Event dictionary lengths: { {key: len(value) for key, value in event.items()} }")
        logging.info(f"Date dictionary lengths: { {key: len(value) for key, value in date.items()} }")
        logging.info(f"Time dictionary lengths: { {key: len(value) for key, value in time.items()} }")
        logging.info(f"IP Address dictionary lengths: { {key: len(value) for key, value in ip_address.items()} }")

        # Ensure all lists have the same length
        def pad_dict(dictionary):
            max_length = max(map(len, dictionary.values()))
            for key in dictionary:
                while len(dictionary[key]) < max_length:
                    dictionary[key].append(None)  # Fill missing values

        pad_dict(event)
        pad_dict(date)
        pad_dict(time)
        pad_dict(ip_address)

        # Convert dictionaries to DataFrames
        events_dict = {
            'EventsTable': pd.DataFrame(event),
            'DateTable': pd.DataFrame(date),
            'TimeTable': pd.DataFrame(time),
            'IpAddressTable': pd.DataFrame(ip_address)
        }

        save_csv(events_dict, LogsData.LOGS_PATH)

        # Merge event DataFrame with type and event type tables
        events_df = events_dict['EventsTable']
        merged_events_df = pd.merge(events_df, type_df, on="type_id", how="left")
        merged_events_df = pd.merge(merged_events_df, event_type_df, on="event_type_id", how="left")

        save_csv({'merged_df': merged_events_df}, LogsData.LOGS_PATH)

        logging.info("CSV files saved successfully.")

    except Exception as e:
        logging.critical(f"Critical error in logs_preprocessing: {e}")


if __name__ == '__main__':
    logs_preprocessing(LogsData.LOGS_PATH + "/logs/")


