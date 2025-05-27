# CS-AWARE-NEXT Dashboard

An interactive **data visualization dashboard** developed for the **CS-AWARE-NEXT project**, providing insights into cybersecurity threats, logs, and related posts. The dashboard leverages the power of [Streamlit](https://streamlit.io/) for seamless user interaction and [Plotly](https://plotly.com/) for creating dynamic, interactive plots.

---

## Features

The dashboard consists of **three main pages**, each designed to address a specific aspect of the cybersecurity landscape:

1. **Threats**  
   - Visualizes the most common threats, including detected malware and malicious IPs sourced from open-source threat intelligence feeds.

2. **Logs**  
   - Displays logs collected from specific organizations, providing an overview of key activities and anomalies.

---

## Technology Stack

- **[Streamlit](https://streamlit.io/):** A Python framework for building interactive web apps with minimal effort.  
- **[Plotly](https://plotly.com/):** A versatile library for creating interactive and visually appealing plots.  

---

## Installation & Usage

### Prerequisites
Ensure you have the following installed on your system:
- Python 3.8 or higher
- Pip (Python package manager)

### Setup
1. Clone this repository:
   ```bash
   git clone https://github.com/your-repo/cs-aware-next-dashboard.git
   cd cs-aware-next-dashboard
   ```
2. Install the requiements:
   ```bash
   pip install -r requirements.txt
   ```
3.  Run the dashboard:
   ```bash
   streamlit run dashboard.py
   ```
