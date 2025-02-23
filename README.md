# Python Traceroute with Scapy

This project implements a traceroute utility in Python using the Scapy library. It provides a deeper understanding of how traceroute works by allowing you to manipulate network packets directly. This was a personal project to explore Scapy and the inner workings of traceroute.

## Features

* **Customizable Destination:** Specify the destination either as a hostname (e.g., google.com) or an IP address (e.g., 8.8.8.8).
* **Adjustable Hop Limit:** Control the maximum number of hops the traceroute will attempt. A default of 64 hops is provided.
* **Scapy Integration:** Leverages the power of Scapy for packet crafting and analysis.


## Usage

1. **Clone the Repository:**

   ```bash
   git clone git@github.com:leonardogs1/TracerouteTool.git
   cd TracerouteTool
   ```

2. **Install Dependencies**
    ```bash
    python3 -m venv .venv  # create virtual env
    source .venv/bin/activate # activate virtual env
    pip install scapy
    ```

3. **Run Script**
    ```bash
    python3 trace-route.py
    ```

4. **Input:**

    The script will prompt you for the following information:

   -  Destination Address: Enter the hostname or IP address of the target destination.
   
   - Maximum Number of Hops (optional): You can specify the maximum number of hops for the traceroute. If you press Enter without entering a value, the script will use the default value of 64 hops.
