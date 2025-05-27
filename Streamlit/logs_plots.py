import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from itertools import cycle

@st.cache_data
def get_event_type_counts(merged_events_df):
    event_type_counts = merged_events_df["event_type"].value_counts().reset_index()
    event_type_counts.columns = ["event_type", "count"]
    total_logs = event_type_counts["count"].sum()
    event_type_counts["percentage"] = (event_type_counts["count"] / total_logs) * 100
    return event_type_counts

@st.cache_data
def generate_color_map(_categories):
    # Convert categories to a hashable type (list)
    categories = list(_categories)
    colors = px.colors.qualitative.T10  # Choose a qualitative color set
    return {category: color for category, color in zip(categories, cycle(colors))}

@st.cache_data
def filter_logs_by_date(merged_events_df, start_date, end_date):
    merged_events_df["datetime"] = pd.to_datetime(merged_events_df["date"] + " " + merged_events_df["time"])
    return merged_events_df[(merged_events_df["datetime"] >= start_date) & (merged_events_df["datetime"] <= end_date)]

def display_treemap_and_radar(merged_events_df, start_date, end_date):
    # Filter logs by date
    filtered_df = filter_logs_by_date(merged_events_df, start_date, end_date)

    event_type_counts = get_event_type_counts(filtered_df)
    categories = event_type_counts["event_type"].tolist()

    # Generate a consistent color map
    color_map = generate_color_map(categories)

    # Treemap
    treemap_fig = px.treemap(
        event_type_counts,
        path=["event_type"],
        values="count",
        title=" ",
        labels={"count": "Count of Logs"},
        color="event_type",
        color_discrete_map=color_map
    )

    treemap_fig.update_layout(
        title_x=0.5,
        margin=dict(t=50, l=25, r=25, b=25)
    )

    # Radar Plot
    values = event_type_counts["count"].tolist()
    radar_fig = go.Figure()
    radar_fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        name='Event Types',
        line=dict(color=color_map[categories[0]])  # Example for first category
    ))

    radar_fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, max(values) + 1])),
        showlegend=False,
        # title="Radar Plot of Event Types",
        plot_bgcolor="white"
    )

    # Display plots side by side
    cols = st.columns([5, 2])  # Treemap (5 parts), Radar (2 parts)
    with cols[0]:
        st.plotly_chart(treemap_fig, use_container_width=True)
    with cols[1]:
        st.plotly_chart(radar_fig, use_container_width=True)

@st.cache_data
def get_logs_per_hour(merged_events_df, start_date, end_date):
    filtered_df = filter_logs_by_date(merged_events_df, start_date, end_date)
    filtered_df["hour"] = filtered_df["datetime"].dt.floor("h")
    logs_per_hour = filtered_df.groupby(["hour", "event_type"]).size().reset_index(name="count")
    sorted_event_types = logs_per_hour.groupby("event_type")["count"].sum().sort_values(ascending=True).index
    logs_per_hour["event_type"] = pd.Categorical(logs_per_hour["event_type"], categories=sorted_event_types, ordered=True)
    return logs_per_hour

def display_streamgraph(merged_events_df, start_date, end_date):
    # Combine date and time into a single datetime column
    merged_events_df["datetime"] = pd.to_datetime(merged_events_df["date"] + " " + merged_events_df["time"])

    # Filter logs by date
    merged_events_df = merged_events_df[(merged_events_df["datetime"] >= start_date) & (merged_events_df["datetime"] <= end_date)]

    # Group by event_type and hour to count logs per hour per category
    merged_events_df["hour"] = merged_events_df["datetime"].dt.floor("h")  # Floor to nearest hour
    logs_per_hour = merged_events_df.groupby(["hour", "event_type"]).size().reset_index(name="count")

    # Sort event types by total count across all hours
    sorted_event_types = logs_per_hour.groupby("event_type")["count"].sum().sort_values(ascending=True).index
    logs_per_hour["event_type"] = pd.Categorical(logs_per_hour["event_type"], categories=sorted_event_types, ordered=True)
    logs_per_hour = logs_per_hour.sort_values(by="event_type")

    # Generate a consistent color map
    categories = logs_per_hour["event_type"].unique()
    color_map = generate_color_map(categories)

    # Create a streamgraph
    fig = px.area(
        logs_per_hour,
        x="hour",  # Time on the x-axis
        y="count",  # Number of logs on the y-axis
        color="event_type",  # Different colors for each event type
        title="Number of Logs Per Hour Per Category",
        labels={"hour": "Time (Hour)", "count": "Number of Logs", "event_type": "Event Type"},
        color_discrete_map=color_map
    )

    # Customize the layout
    fig.update_layout(
        title_x=0.5,  # Center the title
        margin=dict(t=50, l=25, r=25, b=25),  # Adjust margins
        xaxis_title="Time (Hour)",
        yaxis_title="Number of Logs",
        plot_bgcolor="white",  # Set background color to white
        xaxis=dict(gridcolor="lightgrey"),
        yaxis=dict(gridcolor="lightgrey")
    )

    # Display the plot in Streamlit
    st.plotly_chart(fig, use_container_width=True)

def display_top_ip_logs(df, start_date, end_date):
    # Ensure the "date" column is in datetime format
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    # Filter logs by date
    filtered_df = df[(df["date"] >= start_date) & (df["date"] <= end_date)]

    # Display only the date, not the hour
    filtered_df["date"] = filtered_df["date"].dt.date

    # Group by IP and count logs, then filter top 10 IPs
    top_ips = filtered_df["ip_address"].value_counts().head(10).index
    top_ips_filtered = filtered_df[filtered_df["ip_address"].isin(top_ips)]

    # Select only date and IP columns
    result = top_ips_filtered[["date", "ip_address"]]

    # Display the top IP addresses
    st.write("The most frequent IPs are:")
    st.write(result)


