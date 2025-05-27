import streamlit as st
import json
from pathlib import Path
import networkx as nx
from plotly import graph_objects as go

from Utils.data_utils import StreamlitConfig

# Configurartion structure
plotly_config = {
    "layout": {
        "plot_bgcolor": "white",  # White background
        "xaxis": {
            "gridcolor": "lightgrey",  # Grey grid lines on x-axis
            "showgrid": True,  # Explicitly enable vertical grid lines
        },
        "yaxis": {
            "gridcolor": "lightgrey",  # Grey grid lines on y-axis
            "showgrid": True,  # Explicitly enable horizontal grid lines
            "tickmode": "linear",  # Ensure all y-axis values are displayed
            "nticks": 30,  # Number of ticks to show
        },
        "legend": {
            "orientation": "v",  # Vertical legend
            "yanchor": "top",  # Anchor legend to the top
            "y": 1,  # Position legend at the top of the plot
            "xanchor": "left",  # Align the legend to the left
            "x": 1.05  # Place the legend to the right of the plot
        },
        "title": {"x": 0.5}  # Center align the title
    },
    "traces": {
        "line": {"width": 1.5},  # Slimmer line size
        "bar": {  # Bar-specific configuration
            "marker": {"line": {"width": 0.5, "color": "black"}},  # Outline for bars
            "opacity": 0.8  # Slight transparency for better readability
        }
    }
}

def load_themes():
    config_file = Path(StreamlitConfig.CONFIG_PATH)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file {config_file} not found.")
    with open(config_file, "r") as file:
        return json.load(file)

# Get the current theme from the config file
def get_theme():
    themes = load_themes()
    return themes["current_theme"] if "current_theme" in themes else "light"  # Default to light if theme not set

# PLOTS

# Caching data for efficiency
@st.cache_data
def filter_and_group_data(df, start_date, end_date, min_entries=25):
    # Filter the data for the selected date range
    filtered_data = df[
        (df['first_seen'] >= start_date) & (df['last_seen'] <= end_date)
    ]

    # Group the data by malware to calculate the size of bubbles (entry counts)
    malware_data = filtered_data.groupby('malware').agg(
        entries=('ID_ENTRY', 'count'),
        first_seen_min=('first_seen', 'min'),
        last_seen_max=('last_seen', 'max')
    ).reset_index()

    # Filter for malwares with more than the minimum number of entries
    data = malware_data[(malware_data['entries'] > min_entries) & (malware_data['malware'] != 'unknown')]

    return data

@st.cache_data
def get_top_malwares(df, top_k=15):
    # Get the top K malwares by frequency
    return df['malware'].value_counts().nlargest(top_k).index

def plot_combined_malware_reports(df):
    # Get the top 15 malwares based on the number of reports
    top_malwares = df['malware'].value_counts().nlargest(15).index

    # Filter data to include only the top 15 malwares
    filtered_data = df[df['malware'].isin(top_malwares)]

    # Ensure 'first_seen' and 'last_seen' are in datetime format
    filtered_data['first_seen'] = pd.to_datetime(filtered_data['first_seen'], errors='coerce')
    filtered_data['last_seen'] = pd.to_datetime(filtered_data['last_seen'], errors='coerce')

    # Get the minimum and maximum dates for the slider
    min_date = filtered_data['first_seen'].min()
    max_date = filtered_data['last_seen'].max()

    # Convert min_date and max_date to Python datetime (not pandas Timestamps)
    min_date = min_date.to_pydatetime()
    max_date = max_date.to_pydatetime()

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
            key="first_last_slider"
        )

    # Filter the data based on the selected date range
    filtered_data = filtered_data[
        (filtered_data['first_seen'] >= start_date) & (filtered_data['last_seen'] <= end_date)
    ]

    # Group the data by malware to calculate the size of bubbles (entry counts)
    malware_data = filtered_data.groupby('malware').agg(
        entries=('ID_ENTRY', 'count'),
        first_seen_min=('first_seen', 'min'),
        last_seen_max=('last_seen', 'max')
    ).reset_index()

    # Sort the malwares by the number of entries in descending order
    malware_data = malware_data.sort_values(by="entries", ascending=False)

    # Filter for malwares with more than 25 reports
    data = malware_data[(malware_data['entries'] > 25)]

    # Get the current theme (light or dark)
    current_theme = get_theme()
    label_color = "black" if current_theme == "light" else "white"  # Set font color based on the theme
    # Create a bubble chart using Plotly for 'First Seen' vs 'Last Seen'
    fig_first_last = px.scatter(
        data,
        x="first_seen_min",
        y="last_seen_max",
        size="entries",
        color="malware",
        hover_name="malware",
        title="Malware reports over time",
        labels={
            "first_seen_min": "Earliest Reported Threat",
            "last_seen_max": "Latest Reported Threat",
            "entries": "Number of Threat Entries",
            "malware": "Malware"
        },
        size_max=60
    )

    # Apply custom configurations based on the theme
    fig_first_last.update_layout(
        plot_bgcolor=plotly_config["layout"]["plot_bgcolor"],
        xaxis=dict(
            gridcolor=plotly_config["layout"]["xaxis"]["gridcolor"], showgrid=True,
            title_font=dict(color=label_color),
            tickfont=dict(color=label_color)
        ),
        yaxis=dict(
            gridcolor=plotly_config["layout"]["yaxis"]["gridcolor"], showgrid=True,
            tickmode="linear",  # Ensure all values are displayed
            nticks=30,  # Adjust the number of ticks as needed
            title_font=dict(color=label_color),
            tickfont=dict(color=label_color)
        ),
        legend=dict(
            orientation=plotly_config["layout"]["legend"]["orientation"],
            yanchor=plotly_config["layout"]["legend"]["yanchor"],
            y=plotly_config["layout"]["legend"]["y"],
            xanchor=plotly_config["layout"]["legend"]["xanchor"],
            x=plotly_config["layout"]["legend"]["x"],
            font=dict(color=label_color)
        ),
        title=dict(
            text="Malware reports over time",
            x=plotly_config["layout"]["title"]["x"],
            font=dict(color=label_color)
        ),
        width=750,  # Width for the first plot
        height=700
    )

    # Create a bubble chart for 'First Seen' by malware
    # Group by malware again to get the 'entries' count for the second plot
    malware_data_second = filtered_data.groupby(['malware', 'first_seen']).agg(
        entries=('ID_ENTRY', 'count')
    ).reset_index()

    # Sort the second plot data by the number of entries in descending order
    malware_data_second = malware_data_second.sort_values(by="entries", ascending=False)

    fig_first = px.scatter(
        malware_data_second,
        x="first_seen",
        y="malware",
        size="entries",
        color="malware",
        title="Top-15 Malware Threats Over Time",
        labels={
            "first_seen": "First Seen Date",
            "malware": "Malware Name",
            "entries": "Number of Reports"
        },
        size_max=40
    )

    # Apply custom configurations based on the theme
    fig_first.update_layout(
        plot_bgcolor=plotly_config["layout"]["plot_bgcolor"],
        xaxis=dict(
            gridcolor=plotly_config["layout"]["xaxis"]["gridcolor"], showgrid=True,
            title_font=dict(color=label_color),
            tickfont=dict(color=label_color)
        ),
        yaxis=dict(
            gridcolor=plotly_config["layout"]["yaxis"]["gridcolor"], showgrid=True,
            title_font=dict(color=label_color),
            tickfont=dict(color=label_color)
        ),
        legend=dict(
            orientation=plotly_config["layout"]["legend"]["orientation"],
            yanchor=plotly_config["layout"]["legend"]["yanchor"],
            y=plotly_config["layout"]["legend"]["y"],
            xanchor=plotly_config["layout"]["legend"]["xanchor"],
            x=plotly_config["layout"]["legend"]["x"],
            font=dict(color=label_color)
        ),
        title=dict(
            text="Top-15 Malware Threats Over Time",
            x=plotly_config["layout"]["title"]["x"],
            font=dict(color=label_color)
        ),
        width=750,  # Width for the second plot
        height=700
    )

    # Create columns for side-by-side layout
    col1, col2 = st.columns([8, 8])  # Adjust the proportions to control the width
    with col1:
        st.plotly_chart(fig_first_last)

    with col2:
        st.plotly_chart(fig_first)

# Cache top IPs and top malwares to avoid recomputing them on each function call
@st.cache_data
def get_top_ips_and_malwares(df, top_k_ips=30, top_k_malwares=15):
    top_ips = df['ip_address'].value_counts().nlargest(top_k_ips).index
    top_malwares = df['malware'].value_counts().nlargest(top_k_malwares).index
    return top_ips, top_malwares

def plot_interactive_graph(df):
    # Allow the user to select the maximum number of IPs and malwares
    col1, col2 = st.columns([1, 1])  # col1 takes 2 parts and col2 takes 8 parts of the width

    with col1:
        # Allow the user to select the maximum number of IPs (up to 50)
        top_k_ips = st.slider('Select the maximum number of IPs (max 50)', 1, 100, 30)

    with col2:
        # Allow the user to select the maximum number of malwares (up to 25)
        top_k_malwares = st.slider('Select the maximum number of malwares (max 25)', 1, 25, 15)

    # Ensure 'malware' and 'reporter' columns are non-null
    df_no_unknown = df[df['malware'] != 'unknown'].dropna(subset=['ip_address', 'malware', 'reporter'])

    # User selection for nodes to show (IPs must always be selected along with at least one other class)
    st.write("Select 'Reporter' to show the relationship between Malware and Reporter nodes.")
    reporter_checkbox = st.checkbox("Reporter", value=False)

    selected_nodes = []
    if reporter_checkbox:
        selected_nodes.append('Reporter')

    # Extract top IPs and top malwares based on user-defined numbers
    top_ips, top_malwares = get_top_ips_and_malwares(df, top_k_ips, top_k_malwares)

    # Filter the data for these selected top IPs and top malwares
    df_top_ips = df_no_unknown[df_no_unknown['ip_address'].isin(top_ips)]
    df_top_malwares = df_no_unknown[df_no_unknown['malware'].isin(top_malwares)]

    # Create a NetworkX graph
    G = nx.Graph()

    # Add edges between IPs and their associated malwares
    for _, row in df_top_ips.iterrows():
        G.add_edge(row['ip_address'], row['malware'])


    # Add edges between IPs and malwares if selected
    for _, row in df_top_ips.iterrows():
        G.add_edge(row['ip_address'], row['malware'])
    # Add edges between reporters and malwares if selected
    if 'Reporter' in selected_nodes:
        for _, row in df_top_malwares.iterrows():
            G.add_edge(row['reporter'], row['malware'])

    # Use the spring layout for graph positioning (faster than Kamada-Kawai)
    if not reporter_checkbox:
        pos = nx.spring_layout(G, seed=42, k=0.35)
    else:
        pos = nx.spring_layout(G, seed=42, k=0.15)

    # Extract edges for plotting
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])  # Add a None to separate edges
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines',
        showlegend=False
    )

    # Extract nodes for plotting
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_font_size = []

    # Define colors and font sizes for IPs, Malware, and Reporters
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)

        if node in top_ips:
            node_color.append('blue')  # IP addresses (blue)
            node_font_size.append(11)  # IP font size
        elif node in df_no_unknown['reporter'].unique():
            node_color.append('green')  # Reporters (red)
            node_font_size.append(11)  # Reporter font size
        else:
            node_color.append('red')  # Malware (green)
            node_font_size.append(11)  # Malware font size

    # Create the node trace
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        text=node_text,
        textposition="top center",
        hoverinfo='text',
        marker=dict(
            size=10,
            color=node_color,
            line_width=1
        ),
        textfont=dict(size=node_font_size, color = 'black'),
        showlegend=False
    )

    # Create dummy legend traces for IP, Reporter, and Malware nodes
    legend_trace_ip = go.Scatter(
        x=[None], y=[None],  # Invisible trace
        mode='markers',
        marker=dict(size=10, color='blue'),
        name='IP Address',  # Name for legend
        showlegend=True
    )

    legend_trace_malware = go.Scatter(
        x=[None], y=[None],  # Invisible trace
        mode='markers',
        marker=dict(size=10, color='green'),
        name='Malware',  # Name for legend
        showlegend=True
    )

    legend_trace_reporter = go.Scatter(
        x=[None], y=[None],  # Invisible trace
        mode='markers',
        marker=dict(size=10, color='red'),
        name='Reporter',  # Name for legend
        showlegend=True
    )

    # Create the final plot
    fig = go.Figure(data=[edge_trace, node_trace, legend_trace_ip, legend_trace_malware, legend_trace_reporter],
                    layout=go.Layout(
                        title='Malware-Reporter-IP Relationship',
                        titlefont_size=16,
                        showlegend=True,  # Enable the legend
                        hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        plot_bgcolor='white',
                        width=1600,
                        height=700
                    ))

    # Show the plot in Streamlit
    st.plotly_chart(fig)

# Cache the data processing for the first plot to avoid redundant work
@st.cache_data
def process_malware_hierarchy_data(df):
    # Calculate the top 20 malwares based on frequency
    top_malwares = df['malware'].value_counts().nlargest(20).index

    # Filter data to include only the top 20 malwares
    df_top_malwares = df[df['malware'].isin(top_malwares)]

    # Create a Sunburst plot for the hierarchy between source, threat type, and malware
    return px.sunburst(df_top_malwares, path=['source', 'threat_type', 'malware'], title="Hierarchy of the Top 20 malwares")

# Caching the second plot processing
@st.cache_data
def process_malware_aliases_data(df):
    # Calculate the top 20 malwares based on frequency
    top_malwares = df['malware'].value_counts().nlargest(20).index

    # Filter out 'unknown' malwares and only keep top 20 malwares
    df_no_unknown = df[df['malware'] != 'unknown']
    df_top_malwares = df_no_unknown[df_no_unknown['malware'].isin(top_malwares)]

    # Create a Sunburst plot for Malware and their aliases
    return px.sunburst(df_top_malwares, path=['malware', 'alias'], title="Top 20 malwares and their aliases")

def plot_combined_malware_hierarchy_and_aliases(df):
    # Generate the malware hierarchy plot
    fig_hierarchy = process_malware_hierarchy_data(df)

    # Generate the malware aliases plot
    fig_aliases = process_malware_aliases_data(df)

    # Enlarge the plots by adjusting width and height
    fig_hierarchy.update_layout(
        width=600,  # Half the width to show side by side
        height=800  # Adjust height for better view
    )

    fig_aliases.update_layout(
        width=600,  # Half the width to show side by side
        height=800  # Adjust height for better view
    )

    # Create columns for side-by-side layout
    col1, col2 = st.columns(2)

    with col1:
        st.plotly_chart(fig_hierarchy)

    with col2:
        st.plotly_chart(fig_aliases)

# Cache data processing to improve performance
@st.cache_data
def get_filtered_data(df, start_date, end_date):
    # Filter the data based on the selected date range
    filtered_data = df[
        (df['first_seen'] >= pd.to_datetime(start_date)) & (df['first_seen'] <= pd.to_datetime(end_date))
    ]
    return filtered_data

@st.cache_data
def get_state_counts(filtered_data):
    # Group the data by country to calculate the number of malware reports per country
    state_counts = filtered_data.groupby('country').agg(
        report_count=('ID_ENTRY', 'count')  # Count the number of reports (ID_ENTRY column)
    ).reset_index()
    return state_counts

def plot_reports_by_state(df):
    # Convert 'first_seen' to datetime format
    df['first_seen'] = pd.to_datetime(df['first_seen'], errors='coerce')

    # Get the minimum and maximum dates for the slider
    min_date = df['first_seen'].min().date()
    max_date = df['first_seen'].max().date()

    col1, col2 = st.columns([1, 1])  # col1 and col2 take equal width
    with col1:
        start_date = st.date_input("Start Date", value=min_date)
        if start_date < min_date:
            st.error(f"Start date cannot be earlier than the minimum date: {min_date}")

    with col2:
        end_date = st.date_input("End Date", value=max_date)
        if end_date > max_date:
            st.error(f"End date cannot be later than the maximum date: {max_date}")

        # Ensure end date is not earlier than start date
        if end_date < start_date:
            st.error("End date cannot be earlier than the start date.")

    # Ensure end date is after start date
    if start_date > end_date:
        st.error("Start date cannot be later than end date.")
        return

    # Cache and filter the data for the selected date range
    filtered_data = get_filtered_data(df, start_date, end_date)

    # Cache the aggregated state counts
    state_counts = get_state_counts(filtered_data)

    state_counts.rename(columns={'report_count': 'reports'}, inplace=True)

    # Add explicit check for missing data
    if state_counts.empty:
        st.warning("No data available for the selected date range.")
        return

    # Create a choropleth map with report counts in the hover data
    fig = px.choropleth(
        state_counts,
        locations='country',  # The country column
        locationmode='country names',  # Use country names
        color='reports',  # Color by number of reports
        hover_name='country',  # Hover information
        hover_data='reports',  # Explicitly add report count
        title=f'Malware Reports by State from {start_date} to {end_date}',
        color_continuous_scale='aggrnyl'  # Color scale
    )

    # Customize layout
    fig.update_layout(
        width=1600,
        height=700,
        coloraxis_colorbar=dict(title="Report Count")  # Adjust color bar title
    )

    # Show the plot in Streamlit
    st.plotly_chart(fig)

import pandas as pd
import plotly.express as px
import streamlit as st

@st.cache_data
def get_filtered_data(df, start_date, end_date):
    """Filter the data for the selected date range."""
    return df[(df['first_seen'] >= pd.to_datetime(start_date)) & (df['first_seen'] <= pd.to_datetime(end_date))]

@st.cache_data
def get_top_countries(filtered_data):
    """Get the top 10 countries based on the number of reports."""
    return (
        filtered_data['country']
        .value_counts()
        .nlargest(10)
        .index
    )

@st.cache_data
def get_malware_data(filtered_data, _top_countries):
    top_countries_list = list(_top_countries)
    filtered_data = filtered_data[filtered_data['country'].isin(top_countries_list)]
    malware_data = filtered_data.groupby(['malware', 'country', 'first_seen']).agg(
        reports=('ID_ENTRY', 'count')
    ).reset_index()
    return malware_data

def plot_top_countries_malware_reports(df):
    current_theme = get_theme()
    label_color = "black" if current_theme == "light" else "white"

    # Calculate the top 10 countries
    top_countries = list(
        df['country']
        .value_counts()
        .nlargest(10)
        .index
    )

    # Filter data for selected countries
    filtered_data = df[df['country'].isin(top_countries)]

    # Get the minimum and maximum dates
    min_date = df['first_seen'].dropna().min().date()
    max_date = df['first_seen'].dropna().max().date()

    # Center the slider using Streamlit columns
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        start_date, end_date = st.slider(
            "Select date range",
            min_value=min_date,
            max_value=max_date,
            value=(min_date, max_date),
            format="YYYY-MM-DD",
            key="date_range_slider"
        )

    # Convert start_date and end_date to datetime
    start_date = pd.to_datetime(start_date)
    end_date = pd.to_datetime(end_date)

    # Filter data for the selected date range
    malware_data = get_malware_data(filtered_data, top_countries)
    malware_data = malware_data[
        (malware_data['first_seen'] >= start_date) & (malware_data['first_seen'] <= end_date)
    ]

    # Create a bubble chart
    fig = px.scatter(
        malware_data,
        x="first_seen",
        y="country",
        size="reports",
        color="malware",
        title="Malware Reports in Top-10 Countries Over Time",
        labels={
            "country": "Country",
            "first_seen": "First Seen Date",
            "malware": "Malware Name",
            "reports": "Number of Reports"
        },
        size_max=40
    )

    # Apply layout configuration
    fig.update_layout(
        plot_bgcolor=plotly_config["layout"]["plot_bgcolor"],
        xaxis=dict(
            gridcolor=plotly_config["layout"]["xaxis"]["gridcolor"],
            showgrid=True,
            title_font=dict(color=label_color),
            tickfont=dict(color=label_color)
        ),
        yaxis=dict(
            gridcolor=plotly_config["layout"]["yaxis"]["gridcolor"],
            showgrid=True,
            tickmode="linear",  # Ensure all values are displayed
            nticks=30,  # Adjust the number of ticks as needed
            title_font=dict(color=label_color),
            tickfont=dict(color=label_color)
        ),
        legend=dict(
            orientation=plotly_config["layout"]["legend"]["orientation"],
            yanchor=plotly_config["layout"]["legend"]["yanchor"],
            y=plotly_config["layout"]["legend"]["y"],
            xanchor=plotly_config["layout"]["legend"]["xanchor"],
            x=plotly_config["layout"]["legend"]["x"],
            font=dict(color=label_color)
        ),
        title=dict(
            text="Malware reports over time",
            x=plotly_config["layout"]["title"]["x"],
            font=dict(color=label_color)
        ),
        width=950,
        height=700
    )

    # Center the plot using Streamlit columns
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.plotly_chart(fig)



# QUERIES
def query_malware(df):
    # Add a drop-down menu for selecting the malware
    malware_name = st.selectbox("Select the malware:", get_top_malwares(df, 50))

    if malware_name:
        # Filter data for the selected malware
        filtered_data = df[df['malware'].str.contains(malware_name, case=False, na=False)]

        if filtered_data.empty:
            st.warning(f"No data found for malware: {malware_name}")
        else:
            # Calculate frequency
            frequency = filtered_data['malware'].value_counts().iloc[0]

            # Sort IPs per frequency
            ip_addresses = filtered_data['ip_address'].value_counts().index.tolist()

            # Handle NaNs in IP addresses
            ip_addresses = [str(ip) for ip in ip_addresses if pd.notna(ip)]  # Filter out NaNs and convert to strings

            if len(ip_addresses) == 0:  # If no valid IPs remain after filtering
                ip_message = "No IP addresses found"
            else:
                ip_message = ', '.join(ip_addresses[:10])  # Show up to 10 IPs

            reporters = filtered_data['reporter'].unique()

            # Get the status and last period of activity
            last_period = filtered_data[['first_seen', 'last_seen']].agg(['min', 'max'])

            # Convert 'today' to a pandas Timestamp for comparison
            today = pd.to_datetime("today")

            # Access the min and max values from the aggregated results
            last_seen_max = pd.to_datetime(last_period['last_seen']['max'])

            # Compare last seen activity with today's date
            status = "Active" if last_seen_max > today - pd.DateOffset(days=30) else "Inactive"

            # Display the results
            st.write(f"### Malware: {malware_name}")
            st.write(f"**Frequency**: {frequency}")
            st.write(f"**Associated IPs**: {ip_message}")
            st.write(f"**Reporters**: {', '.join(map(str, reporters))}")
            st.write(f"**Status**: {status}")
            st.write(
                f"**Last Period of Activity**: {last_period['first_seen']['min']} to {last_period['last_seen']['max']}")
    else:
        st.warning("Please enter a malware name.")

def query_url(df):

    # User input for URL
    url_input = st.text_input("Enter URL to check for malware association:", "")

    if url_input:
        # Filter data for the given URL
        url_data = df[df['url'].str.contains(url_input, case=False, na=False)]

        if url_data.empty:
            st.warning(f"No malware reports found for URL: {url_input}")
        else:
            # Get associated malwares and their frequency
            associated_malwares = url_data['malware'].value_counts().reset_index()
            associated_malwares.columns = ['malware', 'frequency']

            # Check if the URL is associated with malware
            is_malicious = "Yes" if not associated_malwares.empty else "No"

            # Display the results
            st.write(f"**Is the URL associated with malware?**: {is_malicious}")

            if not associated_malwares.empty:
                st.write("**Associated Malwares**:")
                # Show details of the malwares
                for _, row in associated_malwares.iterrows():
                    malware = row['malware']
                    malware_data = url_data[url_data['malware'] == malware]
                    frequency = row['frequency']
                    st.write(f"- Malware: {malware} (Frequency: {frequency})")
                    st.write(f"  - Reporters: {', '.join(malware_data['reporter'].unique())}")
                    st.write(f"  - Last Activity: {malware_data[['first_seen', 'last_seen']].agg(['min', 'max'])['last_seen']['max']}")
            else:
                st.write(f"No specific malware associated with this URL.")
    else:
        st.warning("Please enter a URL to check.")