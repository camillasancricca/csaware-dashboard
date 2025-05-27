"""
This script contains the main dashboard layout and functionality.

Leonardo Cesani, 4-12-2024
"""
from urllib.parse import urlencode

import requests
import streamlit as st
import pandas as pd
import json
from pathlib import Path
import atexit
import os
from Utils.data_utils import FinalDataERPath, ImagePath, LogsData, PostsAuth, fetch_auth_token
from Streamlit.threats_plots import *
from Streamlit.logs_plots import *
from Streamlit.posts_plots import *
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

# Path to the themes configuration file
CONFIG_FILE = Path(StreamlitConfig.CONFIG_PATH)

# Wide mode for the dashboard
# Configure the page
st.set_page_config(
    page_title="CS-AWARE-NEXT-Dashboard",
    page_icon=ImagePath.TAB_LOGO_PATH,
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load themes configuration from JSON file
def load_themes():
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found.")
    with open(CONFIG_FILE, "r") as file:
        themes = json.load(file)

    # Ensure the theme is set to "light" on startup
    if themes.get("current_theme", "light") != "light":
        themes["current_theme"] = "light"
        save_themes(themes)  # Save the updated theme

    return themes

# Save themes configuration to JSON file
def save_themes(themes):
    with open(CONFIG_FILE, "w") as file:
        json.dump(themes, file, indent=4)

# Initialize session state for themes
ms = st.session_state
if "themes" not in ms:
    ms.themes = load_themes()

# Apply the current theme explicitly during startup
def apply_theme():
    theme_dict = ms.themes[ms.themes["current_theme"]]
    for key, value in theme_dict.items():
        if key.startswith("theme"):
            st._config.set_option(key, value)

apply_theme()  # Enforce the theme on app startup

def change_theme():
    # Toggle between light and dark themes
    current_theme = ms.themes["current_theme"]
    ms.themes["current_theme"] = "light" if current_theme == "dark" else "dark"

    # Apply the selected theme
    apply_theme()

    # Save the updated theme state
    save_themes(ms.themes)


# Load data from the final CSV file
@st.cache_data
def load_threats_data():
    data = pd.read_csv(FinalDataERPath.SAVE_PATH + "Data.csv", low_memory=False)
    return data

@st.cache_data
def load_logs_data():
    data = pd.read_csv(LogsData.LOGS_PATH + "merged_df.csv", low_memory=False)
    return data

@st.cache_data
def load_logs_ip_data():
    data = pd.read_csv(LogsData.LOGS_PATH + "IpAddressTable.csv", low_memory=False)
    return data


API_BASE_URL = "http://52.48.88.83:8000/social_media/observation/search/keywords"


@st.cache_data
def fetch_posts_data(keywords, selected_date, limit, source_types, display_languages):
    """Fetches posts from the API based on keywords, selected date, multiple sources, multiple languages, and response limit."""

    # Ensure the token is correctly formatted
    access_token = str(PostsAuth.ACCESS_TOKEN).strip()

    headers = {
        "accept": "application/json",
        "access-token": access_token,
        "Content-Type": "application/json"
    }

    # Convert date to correct format
    newer_than = selected_date.strftime("%Y-%m-%dT%H:%M:%S")

    # Validate limit
    limit = max(1, min(limit, 100))  # Ensure it's between 1-100

    # Store results from multiple sources & languages
    combined_posts = []

    for source in source_types:
        for language in display_languages:
            # Query parameters for each source & language
            params = {
                "sourceType": source,
                "targetLanguage": language,
                "newerThan": newer_than,
                "order_by": "observation_created",
                "direction": "asc",
                "limit": limit,
                "offset": 0
            }

            url = f"{API_BASE_URL}?{urlencode(params)}"

            # API Request
            payload = {"keywords": keywords}

            try:
                response = requests.post(url, headers=headers, json=payload)
                response.raise_for_status()  # Raises an error for HTTP failures (4xx, 5xx)
                data = response.json()

                # Check for valid response structure
                if "entries" not in data or not isinstance(data["entries"], list):
                    st.warning(f"Invalid response format for {source} ({language}). Skipping...")
                    continue

                # Extract metadata
                #page_info = data.get("pageInfo", {})
                #total_entries = page_info.get("totalCount", 0)

                #st.info(f"{source.capitalize()} ({language}): {total_entries} posts available.")

                # Extract relevant fields from each entry
                for entry in data["entries"]:
                    combined_posts.append({
                        "Source Type": entry.get("sourcetype", source.capitalize()),
                        "Language": language,
                        "Post ID": entry.get("post_id", "N/A"),
                        "Text": entry.get("body", ""),
                        "Created At": entry.get("observation_created", "N/A"),
                        "Account Name": entry.get("account_name", "N/A"),
                        "Display Name": entry.get("account_displayname", "N/A"),
                        "Account Description": entry.get("account_description", "N/A"),
                    })

            except requests.exceptions.RequestException as e:
                st.error(f"API request failed for {source} ({language}): {e}")

    # Convert to DataFrame
    return pd.DataFrame(combined_posts) if combined_posts else pd.DataFrame()

@st.cache_data
def get_min_max_dates(data):
    # Combine the "date" and "time" columns into a single datetime column
    data["datetime"] = pd.to_datetime(data["date"] + " " + data["time"])

    # Calculate the minimum and maximum datetime values
    min_datetime = data["datetime"].min().to_pydatetime()
    max_datetime = data["datetime"].max().to_pydatetime()
    return min_datetime, max_datetime

# Main dashboard with tabs
def main():
    st.image(ImagePath.LOGO_PATH, width=850)
    st.title("CS-AWARE-NEXT Data Visualization Dashboard")

    # Create top-right corner layout
    col1, col2 = st.columns([9, 1])  # Adjust column proportions
    with col2:
        # Place the theme toggle button in the top-right corner
        btn_face = (
            ms.themes["light"]["button_face"]
            if ms.themes["current_theme"] == "light"
            else ms.themes["dark"]["button_face"]
        )
        st.button(btn_face, on_click=change_theme)

    if ms.themes["refreshed"] == False:
        ms.themes["refreshed"] = True
        st.rerun()

    # Add tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["Home", "Threats", "Logs", "Posts"])

    with tab1:
        st.header("Home")
        st.write("Welcome to the interactive dashboard with data visualizations!")

        # Hero Section with Highlighted Features
        st.markdown("""
        ### 🌟 Unlock Insights, Stay Secure!
        Explore a world of **cybersecurity insights** and **malware trends** through our interactive dashboard. Whether you're a cybersecurity expert, analyst, or just curious about the latest trends, this tool is designed to empower you with actionable data.
        """)

        # About Section
        st.subheader("About CS-AWARE-NEXT")
        st.write("""
        **CS-AWARE-NEXT** is a pioneering initiative dedicated to enhancing cybersecurity awareness and collaboration within local and regional networks. Building upon the success of the **CS-AWARE** project, CS-AWARE-NEXT focuses on providing improved cybersecurity management capabilities to organizations and local/regional supply networks, enabling them to effectively address the dynamic cybersecurity landscape and comply with European legislation such as the **NIS directive**.

        #### Key Objectives:
        - Strengthen **cybersecurity awareness** within local and regional ecosystems.
        - Provide **data-driven tools** for effective threat analysis and response.
        - Align organizations with European cybersecurity frameworks.

        For more information, visit our [website](https://www.cs-aware-next.eu/).
        """)

        # Explore the Dashboard
        st.subheader("🚀 Explore the Dashboard")
        st.markdown("""
        Dive into the heart of cybersecurity with the following interactive sections:

        #### 🔐 **Threats**
        - **Visualize Malware Trends**: Examine malware trends over time by exploring their **first seen** and **last seen** dates.
        - **Interactive Plots**: Observe **report frequencies** and spot patterns with intuitive visualizations.
        - **Malware Relationships**: Discover how different malwares are related through **hierarchies and aliases**.
        - **Detailed Malware Insights**: Access insights on **specific malwares**, including their **IPs**, **activity status**, and **frequency**.
        - **Malicious URL Checker**: Determine if a URL is flagged as **malicious** and explore its activity history.
        - **Global Threat Heatmap**: Visualize the distribution of malware reports by country over time with an **interactive map**.
        - **Network Graphs**: Explore relationships between **IPs**, **malwares**, and **reporters** with an interactive network graph.

        #### 🗂️ **Logs**
        - **Filter Logs by Date**: Use the **date range slider** to refine logs based on your selected time period.
        - **Event Frequencies**: Analyze the **distribution of event types** and their relative importance.
        - **Most Frequent IPs**: View the **most frequent IPs**.

        #### 📰 **Posts**
        - **Keyword-Based Filtering**: Select a keyword sorted by **relevancy (frequency)** to filter relevant posts.
        - **Top Recent Posts**: View the **titles and descriptions** of the top 5 most recent posts for a selected keyword.

        #### 🎯 **Why Use This Dashboard?**
        - Simplify complex cybersecurity data with **intuitive visualizations**.
        - Identify patterns and trends quickly to **stay ahead of threats**.
        - Empower decision-making with **real-time insights** into logs, malware activity, and posts.

        ---

        🌐 **Start Exploring Now** and transform how you approach cybersecurity!
        """)

        # Add a call to action
        st.markdown("""
        ### Ready to Secure Your Network?
        Navigate to the **Threats**, **Logs**, and **Posts** tabs to start analyzing your data and uncover actionable insights!
        """)

        # Footer Section
        st.markdown("---")
        st.markdown("""
        ##### 👨‍💻 Designed and Built by **Leonardo Cesani** [![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/leonardo-cesani-489842265/)
        """)

    with tab2:
        st.header("Threats")
        data_threats = load_threats_data()

        # Plot malware reports over time (both first and last seen)
        st.title("Malware Reports Over Time")
        st.write("In the plot to the left you can see the relation between the first and last seen dates of the malware reports and the number of reports per malware. The larger the bubble, the more reports there are for that malware. In the plot to the right you can see how the number of reports per malware evolves over time. The larger the bubble, the more reports there are for that malware.")
        st.write("Use the slider to filter the start and end date of the analysis.")
        plot_combined_malware_reports(data_threats)

        # Plot malware hierarchy
        st.title("Malware Hierarchy and Aliases")
        st.write("In the plot to the left you can see how different malwares are reported by different sources. In the plot to the right you can see the different aliases of the malwares.")
        st.write("Click on a source's name or malware's name to get more information.")
        plot_combined_malware_hierarchy_and_aliases(data_threats)

        st.title("🔍 Malware Insights")
        st.write(
            "Explore detailed information about malware, including frequency, associated IPs, reporters, and activity status.")
        query_malware(data_threats)

        st.title("🌐 Malicious URL Checker")
        st.write(
            "Identify whether a URL is associated with known malware and get insights about its malicious activity.")
        query_url(data_threats)

        # Plot the networks of IPs, makwares and reporters
        st.title("Network of IPs, Malwares and Reporters")
        st.write('In this plot it is possible to visualize the network of IPs, malwares and reporters. By selecting Reporters, it is possible to add to the network the reporters that reported the malwares.')
        plot_interactive_graph(data_threats)

        # Plot the map world colored by the number of reports
        st.title("Reports by Country")
        st.write("In this plot it is possible to visualize the number of reports per country in a specific temporal range.")
        plot_reports_by_state(data_threats)


        # Plot reports per state in a time range
        st.title("Reports by Country")
        st.write("In this plot it is possible to visualize the number of reports per state in a specific temporal range.")
        plot_top_countries_malware_reports(data_threats)


    with tab3:
        st.header("Logs")

        data_logs = load_logs_data()
        data_ip_logs = load_logs_ip_data()

        st.write("Use the slider to filter the logs by date.")
        # Get the minimum and maximum dates for the slider

        # Convert min_date and max_date to Python datetime (not pandas Timestamps)
        min_date, max_date = get_min_max_dates(data_logs)

        # Use columns layout to reduce the width occupied by sliders
        col1, col2 = st.columns([1, 2])  # Adjust columns' proportions
        with col1:
            # Date range slider for selecting the range of dates (slightly reduced width)
            start_date, end_date = st.slider(
                "Select date range",
                min_value=min_date,
                max_value=max_date,
                value=(min_date, max_date),
                format="YYYY-MM-DD",
                key="logs_date_slider"
            )

        # Treemap visualization of the logs
        st.title("Visualization of Event Type Frequencies")
        st.write("In this plot it is possible to visualize the fraction of an event type with respect all the available logs.")
        display_treemap_and_radar(data_logs, start_date, end_date)

        # Streamgraph
        st.title("Evolution of Different Types of Logs in Time")
        st.text("In this plot it is possible to visualize the evolution of the frequency of different types of logs.")
        display_streamgraph(data_logs, start_date, end_date)

        # Show the top 10 logs discovered in the logs
        st.title("Top 10 Most Frequent Logs")
        st.write("In this table it is possible to visualize the top 10 most frequent logs.")
        display_top_ip_logs(data_ip_logs, start_date, end_date)

    with tab4:
        st.header("Search Social Media Posts")

        # **User Input: Keywords and Date Selection**
        keywords = st.text_input("Enter keywords (comma-separated)", "linux", key="keywords_input")
        selected_date = st.date_input("Select date", datetime.today(), key="date_input")

        # **Multi-select source type (Twitter and/or Reddit)**
        source_types = st.multiselect("Select source types", ["twitter", "reddit"], default=["twitter", "reddit"],
                                      key="source_type_input")

        # **Multi-select display languages**
        display_languages = st.multiselect("Select display languages", ["da", "de", "el", "en", "fr", "it", "sv"],
                                           default=["en"], key="language_input")

        # **User selects the number of responses**
        limit = st.slider("Select the number of posts to retrieve", min_value=1, max_value=100, value=10,
                          key="limit_input")

        # **Button to fetch data ONLY when clicked**
        if st.button("Search Posts", key="search_button"):
            st.session_state["fetch_data"] = True  # Set flag to trigger API call

        # **Run API only if button was clicked**
        if st.session_state.get("fetch_data", False):
            keywords_list = [kw.strip() for kw in keywords.split(",") if kw.strip()]

            if keywords_list and source_types and display_languages:
                with st.spinner("Fetching posts..."):
                    # Set auth token for posts API
                    fetch_auth_token()
                    results_df = fetch_posts_data(keywords_list, selected_date, limit, source_types, display_languages)

                if not results_df.empty:
                    st.dataframe(results_df)  # Show data in a table
                else:
                    st.warning("No results found.")

                # Reset flag after fetching
                st.session_state["fetch_data"] = False
            else:
                st.warning("Please enter at least one keyword, select at least one source, and one language.")

if __name__ == "__main__":
    main()
