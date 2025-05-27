import pandas as pd
import streamlit as st

@st.cache_data
def compute_keyword_counts(df):
    """
    Compute the frequency of keywords in the DataFrame.

    Args:
        df (pd.DataFrame): DataFrame containing the 'keyword' column.

    Returns:
        pd.DataFrame: DataFrame with keywords and their counts, sorted by relevancy.
    """
    keyword_counts = df['keyword'].value_counts().reset_index()
    keyword_counts.columns = ['keyword', 'count']
    keyword_counts.sort_values(by='count', ascending=False, inplace=True)
    return keyword_counts

@st.cache_data
def filter_by_keyword(df, keyword):
    """
    Filter the DataFrame by the selected keyword and sort by data_created.

    Args:
        df (pd.DataFrame): Original DataFrame.
        keyword (str): Selected keyword.

    Returns:
        pd.DataFrame: Filtered and sorted DataFrame.
    """
    filtered_df = df[df['keyword'] == keyword]
    filtered_df.sort_values(by='data_created', ascending=False, inplace=True)
    return filtered_df

def display_recent_titles_and_bodies(df):
    """
    Streamlit dashboard function to select a keyword by relevancy and display top 5 recent entries.

    Args:
        df (pd.DataFrame): DataFrame with columns title, body, sourcetype, language, data_created, keyword.
    """
    st.title("Keyword-Based Content Viewer")

    # Ensure the data_created column is a datetime object
    df['data_created'] = pd.to_datetime(df['data_created'])

    # Compute keyword counts with caching
    keyword_counts = compute_keyword_counts(df)

    # Display the keyword selection dropdown
    selected_keyword = st.selectbox(
        "Select a keyword (sorted by relevancy):",
        options=keyword_counts['keyword'].tolist()
    )

    # Filter the DataFrame by the selected keyword with caching
    filtered_df = filter_by_keyword(df, selected_keyword)

    # Display the top 5 most recent entries
    st.header(f"Top 5 Recent Entries for '{selected_keyword}'")

    for _, row in filtered_df.head(5).iterrows():
        st.subheader(row['title'])
        st.write(row['body'])
        st.write(f"Source Type: {row['sourcetype']}, Language: {row['language']}")
        st.write(f"Date Created: {row['data_created'].strftime('%Y-%m-%d %H:%M:%S')}")
        st.write("---")