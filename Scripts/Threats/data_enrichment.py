"""
Data enrichment for the final ER schemas.

Leonardo Cesani, 25-11-2024
"""

# Libraries
import pandas as pd
import logging
import warnings
from collections import Counter
from Utils.data_utils import DataERPath, ERSchemas, save_csv

# Set up logging to include a custom prefix and function name
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s] - %(funcName)s - %(message)s')

# Disable warnings
warnings.filterwarnings("ignore")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def malware_list_builder(malwares_df, alias_df):
    """
    Create a list of malware from the malware and alias DataFrames.

    :param malware_df: DataFrame containing malware names.
    :param alias_df: DataFrame containing malware-alias relationships.
    """
    try:
        malwares_list = list(set(malwares_df['malware']))
        for i in range(len(malwares_list)):
            data = {
                'malware': malwares_list[i], 'alias': malwares_list[i]
            }
            df_1 = pd.DataFrame([data])

            alias_df = pd.concat([alias_df, df_1], ignore_index=True)

        return alias_df
    except Exception as e:
        logging.error(f"Error building malware list: {e}")
        raise

def jaro_Winkler(s1, s2):
    """
    Calculate the Jaro-Winkler similarity between two strings.

    :param s1: The first string.
    :param s2: The second string.
    :return: The Jaro-Winkler similarity score between the two strings.
    """
    try:
        # Calculate the Jaro distance between two strings
        jaro_dist = jaro_distance(s1, s2)

        # If the Jaro distance is above a certain threshold, apply the Winkler adjustment
        if (jaro_dist > 0.7):
            # Find the length of the common prefix between the two strings
            prefix = 0
            for i in range(min(len(s1), len(s2))):
                if (s1[i] == s2[i]):
                    prefix += 1
                else:
                    break;

            # Limit the maximum prefix length to 4
            prefix = min(4, prefix)

            # Calculate the final Jaro-Winkler similarity by adding a bonus for the common prefix
            jaro_dist += 0.1 * prefix * (1 - jaro_dist)

        return jaro_dist
    except Exception as e:
        logging.error(f"Error calculating Jaro-Winkler similarity: {e}")
        raise

def jaro_distance(s1, s2):
    """
    Calculate the Jaro distance between two strings.

    :param s1: The first string.
    :param s2: The second string.
    :return: The Jaro distance similarity score between the two strings.
    """
    try:
        # If the strings are identical, return maximum similarity
        if (s1 == s2):
            return 1.0

        # Get the length of both strings
        len1 = len(s1)
        len2 = len(s2)

        # If either string is empty, return zero similarity
        if (len1 == 0 or len2 == 0):
            return 0.0

        # Maximum distance up to which matching is allowed
        max_dist = (max(len(s1), len(s2)) // 2) - 1

        # Count of matches
        match = 0

        # Hash arrays to keep track of matches in both strings
        hash_s1 = [0] * len(s1)
        hash_s2 = [0] * len(s2)

        # Traverse through the first string and look for matches in the second string within the allowed distance
        for i in range(len1):
            for j in range(max(0, i - max_dist), min(len2, i + max_dist + 1)):
                if (s1[i] == s2[j] and hash_s2[j] == 0):
                    hash_s1[i] = 1
                    hash_s2[j] = 1
                    match += 1
                    break

        # If no matches are found, return zero similarity
        if (match == 0):
            return 0.0

        # Calculate the number of transpositions
        t = 0
        point = 0
        for i in range(len1):
            if (hash_s1[i]):
                while (hash_s2[point] == 0):
                    point += 1
                if (s1[i] != s2[point]):
                    t += 1
                point += 1

        t /= 2

        # Return the Jaro similarity
        return ((match / len1 + match / len2 + (match - t) / match) / 3.0)
    except Exception as e:
        logging.error(f"Error calculating Jaro distance: {e}")
        raise

def compute_matrix(lista_riga, lista_colonna):
    """
    Compute the Jaro-Winkler similarity matrix for two lists of strings.

    :param lista_riga: List of strings for the rows.
    :param lista_colonna: List of strings for the columns.
    :return: A DataFrame representing the similarity matrix.
    """
    try:
        logging.info("Computing similarity matrix...")
        # Create an empty DataFrame with row and column labels from the provided lists
        df = pd.DataFrame()
        df.index = lista_riga
        df.rename(columns=lista_colonna, inplace=True)

        # Calculate the Jaro-Winkler similarity for each pair of strings and store it in the DataFrame
        for i in range(len(lista_riga)):
            for j in range(len(lista_colonna)):
                string1 = lista_riga[i]
                string2 = lista_colonna[j]
                jaro_wrinkler = jaro_Winkler(string1, string2)
                df.loc[string1, string2] = jaro_wrinkler

        return df
    except Exception as e:
        logging.error(f"Error computing similarity matrix: {e}")
        raise

def search_similarity(df, alpha):
    """
    Search for pairs of strings with similarity above a given threshold in a DataFrame.

    :param df: DataFrame containing similarity scores.
    :param alpha: Threshold for similarity.
    :return: A DataFrame containing pairs of strings with similarity above the threshold.
    """
    try:
        logging.info("Searching for similarities above threshold...")
        # Create an empty DataFrame to store similar pairs
        dataframe = pd.DataFrame()

        # Get the list of row and column labels from the input DataFrame
        indexes = list(df.index)
        columns = list(df.columns)

        # Iterate over each element in the DataFrame
        for i in range(len(indexes)):
            for j in range(len(columns)):
                x = indexes[i]
                y = columns[j]
                element = df.at[x, y]

                # If the similarity is greater than the threshold (alpha), add the pair to the new DataFrame
                if ((element > alpha)):
                    data = {'malware_OR_alias': [y], 'tag': [x]}
                    temp = pd.DataFrame(data)
                    dataframe = pd.concat([dataframe, temp], ignore_index=True)

        return dataframe
    except Exception as e:
        logging.error(f"Error searching for similarities: {e}")
        raise

def add_associated_malware(tags, similarities, alias):
    """
    Add associated malware information to tags based on similarity scores.

    :param tags: DataFrame containing tags.
    :param similarities: DataFrame containing similarity pairs.
    :param alias: DataFrame containing malware-alias relationships.
    :return: Updated DataFrame with associated malware information.
    """
    try:
        logging.info("Adding associated malware to tags...")
        # Get the list of unique malwares from the alias DataFrame
        malwares = list(set(alias.malware))

        # Iterate over each tag in the tags DataFrame
        for i in range(len(tags)):
            tag = tags.at[i, 'tag']
            similarity_df = similarities[similarities.tag == tag].reset_index(drop=True)
            similarity_list = list(similarity_df['malware_OR_alias'])

            # If there are similar aliases, find the associated malware
            if (len(similarity_list) > 0):
                dataframe = pd.DataFrame()
                for j in range(len(similarity_list)):
                    similarity_element = similarity_list[j]
                    match_df = alias[alias.alias == similarity_element].reset_index(drop=True)
                    dataframe = pd.concat([dataframe, match_df])

                # Get the unique malwares associated with the tag
                malware = list(set(dataframe['malware']))

                # If there is only one associated malware, assign it to the tag
                if (len(malware) == 1):
                    tags.at[i, 'Ass.Malware'] = malware[0]

        return tags
    except Exception as e:
        logging.error(f"Error adding associated malware to tags: {e}")
        raise

def majority_vote(lst):
    """
    Determine the most common element in a list (majority vote).

    :param lst: List of elements.
    :return: The element with the highest occurrence in the list.
    """
    try:
        # Count the occurrences of each element in the list
        counts = Counter(lst)

        # Find and return the element with the maximum count (i.e., the majority vote)
        most_common_element = max(counts, key=counts.get)
        return most_common_element
    except Exception as e:
        logging.error(f"Error calculating majority vote: {e}")
        raise

def assign_malware(entries, new_tags):
    """
    Assign malware to entries based on associated tags.

    :param entries: DataFrame containing entries.
    :param new_tags: DataFrame containing tags and associated malware.
    :return: Updated entries DataFrame with malware assignments.
    """
    try:
        # Iterate over each entry in the entries DataFrame
        for i in range(len(entries)):
            malware = entries.at[i, 'malware']
            id_entry = entries.at[i, 'ID_ENTRY']
            source = entries.at[i, 'source']

            # If the malware field is not assigned, find associated malwares from the tags DataFrame
            if not isinstance(malware, str):
                malwares = list(new_tags[(new_tags['Ass.Malware'] != '') & (new_tags.ID_ENTRY == id_entry) & (
                            new_tags.source == source)]['Ass.Malware'])
                if (len(malwares) >= 1):
                    entries.at[i, 'malware'] = majority_vote(malwares)
        logging.info("Malware assignment completed successfully.")
    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while assigning malware to entries: {e}")
        raise

    return entries

def verifica_presenza(parole_chiave, stringa):
    """
    Check if any of the keywords are present in the given string.

    :param parole_chiave: List of keywords to check for.
    :param stringa: The string to check within.
    :return: True if any keyword is present, False otherwise.
    """
    try:
        for parola_chiave in parole_chiave:
            if parola_chiave.lower() in stringa.lower():
                return True
        return False
    except Exception as e:
        logging.error(f"Error checking keyword presence: {e}")
        raise

def categorize_tags(tags_df):
    """
    Categorizes the tags in the DataFrame based on malware types and adds binary columns for each type.

    :param tags_df: DataFrame containing the 'tag' column to categorize.
    :return: A DataFrame with additional columns representing different malware categories.
    """
    try:
        logging.info("Starting to categorize tags...")

        # Copy the original DataFrame
        tags_categorized = tags_df.copy()

        # Initialize columns for each category
        categories = ['worm', 'trojan', 'ransomware', 'rootkit', 'spyware', 'adware', 'botnet', 'keylogger', 'dropper',
                      'backdoor', 'downloader']
        for category in categories:
            tags_categorized[category] = 0
        logging.info("Initialized columns for each malware category.")

        # Define keywords for each category
        keywords = {
            'worm': ['worm', 'w0rm', 'slam'],
            'trojan': ['rat', 'trj', 'troj'],
            'ransomware': ['ransom', 'crypt', 'lock'],
            'rootkit': ['root', 'kit'],
            'spyware': ['spy', 'steal'],
            'adware': ['adw'],
            'botnet': ['bot', 'c2', 'cc'],
            'keylogger': ['key', 'keylog'],
            'dropper': ['drop', 'drp'],
            'backdoor': ['bd', 'back', 'door'],
            'downloader': ['down', 'dl', 'load']
        }

        # Iterate over each tag and assign categories
        for i in range(len(tags_categorized)):
            tag_name = tags_categorized.at[i, 'tag']

            for category, parole_chiave in keywords.items():
                if verifica_presenza(parole_chiave, tag_name):
                    tags_categorized.loc[i, category] = 1
        logging.info("Finished categorizing tags.")

        return tags_categorized

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while categorizing tags: {e}")
        raise

def categorize_aliases(alias_df):
    """
    Categorizes the aliases in the DataFrame based on malware types and adds binary columns for each type.

    :param alias_df: DataFrame containing the 'alias' column to categorize.
    :return: A DataFrame with additional columns representing different malware categories.
    """
    try:
        logging.info("Starting to categorize aliases...")

        # Copy the original DataFrame
        alias_categorized = alias_df.copy()

        # Initialize columns for each category
        categories = ['worm', 'trojan', 'ransomware', 'rootkit', 'spyware', 'adware', 'botnet', 'keylogger', 'dropper',
                      'backdoor', 'downloader']
        for category in categories:
            alias_categorized[category] = 0
        logging.info("Initialized columns for each malware category.")

        # Define keywords for each category
        keywords = {
            'worm': ['worm', 'w0rm', 'slam'],
            'trojan': ['rat', 'trj', 'troj'],
            'ransomware': ['ransom', 'crypt', 'lock'],
            'rootkit': ['root', 'kit'],
            'spyware': ['spy', 'steal'],
            'adware': ['adw'],
            'botnet': ['bot', 'c2', 'cc'],
            'keylogger': ['key', 'keylog'],
            'dropper': ['drop', 'drp'],
            'backdoor': ['bd', 'back', 'door'],
            'downloader': ['down', 'dl', 'load']
        }

        # Iterate over each alias and assign categories
        for i in range(len(alias_categorized)):
            tag_name = alias_categorized.at[i, 'alias']

            for category, parole_chiave in keywords.items():
                if verifica_presenza(parole_chiave, tag_name):
                    alias_categorized.loc[i, category] = 1
        logging.info("Finished categorizing aliases.")

        return alias_categorized

    except KeyError as e:
        logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
        raise
    except Exception as e:
        logging.error(f"An error occurred while categorizing aliases: {e}")
        raise

class ERDataEnrichment:
    def __init__(self):
        # Paths to save data
        self.save_directory = DataERPath.SAVE_PATH
        self.path_ENTRIES = self.save_directory + ERSchemas.ENTRIES + '.csv'
        self.path_TAGS = self.save_directory + ERSchemas.TAGS + '.csv'
        self.path_ALIAS = self.save_directory + ERSchemas.ALIAS + '.csv'
        self.path_MALWARES = self.save_directory + ERSchemas.MALWARES + '.csv'

        # Data frames
        self.ENTRIES_df = None
        self.TAGS_df = None
        self.ALIAS_df = None
        self.MALWARES_df = None

        self.load_data()

    def load_data(self):
        """
        Load the final ER schemas.
        """
        try:
            logging.info("Loading the final ER schemas...")
            self.ENTRIES_df = pd.read_csv(self.path_ENTRIES, low_memory=False)
            self.TAGS_df = pd.read_csv(self.path_TAGS, low_memory=False)
            self.ALIAS_df = pd.read_csv(self.path_ALIAS, low_memory=False)
            self.MALWARES_df = pd.read_csv(self.path_MALWARES, low_memory=False)
        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    def enrich(self):
        """
        Enrich the final ER schemas.
        """
        try:
            logging.info("Starting enrichment of the final ER schemas...")

            # first,

            # Enrich the ALIAS ER schema
            logging.info("Enriching the ALIAS ER schema...")
            self.ALIAS_df = malware_list_builder(self.MALWARES_df, self.ALIAS_df)
            self.ALIAS_df = self.ALIAS_df.drop_duplicates().reset_index(drop=True)

            # Similarity enrichment
            logging.info("Performing similarity enrichment...")
            malware_list = list(set(self.ALIAS_df['malware']))
            alias_list = list(set(self.ALIAS_df['alias']))
            tag_list = list(set(self.TAGS_df['tag']))

            malware_words = list(set(malware_list + alias_list))

            jaro_wrinkler_matrix = compute_matrix(tag_list, malware_words)
            similarity_dataframe = search_similarity(jaro_wrinkler_matrix, 0.8)
            similarity_dataframe = similarity_dataframe.drop_duplicates().reset_index(drop=True)

            # Update tags with associated malware
            logging.info("Updating tags with associated malware...")
            new_tags_df = self.TAGS_df.copy()
            new_tags_df['Ass.Malware'] = ''
            new_tags_df = add_associated_malware(new_tags_df, similarity_dataframe, self.ALIAS_df)

            # Assign malware to entries
            logging.info("Assigning malware to entries...")
            entries_assigned = assign_malware(self.ENTRIES_df, new_tags_df)
            enriched_entries = entries_assigned
            enriched_entries.loc[enriched_entries.malware.isna(), 'malware'] = 'unknown'

            # Enrich aliases
            logging.info("Enriching aliases...")
            new_alias = pd.DataFrame()
            new_tags_df = new_tags_df[(new_tags_df['Ass.Malware'] != '')]
            new_alias[['alias', 'malware']] = new_tags_df[['tag', 'Ass.Malware']]
            new_alias = new_alias.drop_duplicates()

            alias_updated = pd.concat([self.ALIAS_df, new_alias], axis=0)
            alias_updated = alias_updated.drop_duplicates().reset_index(drop=True)
            enriched_alias = alias_updated

            # Categorize enriched aliases
            logging.info("Categorizing enriched aliases...")
            alias_categorized = categorize_aliases(alias_updated)
            grouped_df = alias_categorized[['malware', 'worm', 'trojan', 'ransomware', 'rootkit',
                                            'spyware', 'adware', 'botnet', 'keylogger', 'dropper', 'backdoor',
                                            'downloader']].groupby('malware').sum()
            max_column = grouped_df.idxmax(axis=1)

            # Assign 'unknown' if no category matches
            max_column[grouped_df.sum(axis=1) == 0] = 'unknown'
            type_df = pd.DataFrame(max_column).reset_index()

            for i in range(len(type_df)):
                m = type_df.at[i, 'malware']
                t = type_df.at[i, 0]
                self.MALWARES_df.loc[self.MALWARES_df['malware'] == m, 'type'] = t

            enriched_malwares = self.MALWARES_df

            # Categorize tags
            logging.info("Categorizing tags...")
            old_tags = categorize_tags(self.TAGS_df)
            max_greater_than_zero = old_tags.iloc[:, 3:-1].max(axis=1) >= 1
            colonna_maggiore = old_tags.iloc[:, 3:-1].idxmax(axis=1)
            old_tags['type'] = ''
            colonna_maggiore = old_tags.iloc[:, 3:-1].idxmax(axis=1)
            max_greater_than_zero = old_tags.iloc[:, 3:-1].max(axis=1) == 0
            old_tags['type'] = colonna_maggiore

            old_tags.loc[max_greater_than_zero, 'type'] = 'unknown'
            tag_columns = ['ID_ENTRY', 'source', 'tag', 'type']
            enriched_tags = old_tags[tag_columns]

            # Save the dataframes
            logging.info("Saving enriched ER schemas...")
            dataframes_dict = {
                'Entries': enriched_entries,
                'Tags': enriched_tags,
                'Alias': enriched_alias,
                'Malwares': enriched_malwares
            }

            save_csv(dataframes_dict, self.save_directory)
            logging.info("Enrichment and saving of ER schemas completed successfully.")

        except KeyError as e:
            logging.error(f"KeyError: {e} - One or more expected columns are missing in the input DataFrame.")
            raise
        except Exception as e:
            logging.error(f"An error occurred during the enrichment process: {e}")
            raise

def enrich():
    ERDataEnrichment().enrich()

if __name__ == '__main__':
    enrich()








