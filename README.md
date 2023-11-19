# IOC validation tool

This Python script facilitates interactions with multiple cybersecurity APIs including VirusTotal, MalwareBazaar, and AbuseIPDB. It's designed for security analysts, researchers, and enthusiasts who require automated querying and data retrieval from these services.

## Description

This tool automates the process of sending HTTP requests to different cybersecurity APIs. It handles requests and responses effectively, allowing users to quickly gather and analyze data from VirusTotal, MalwareBazaar, and AbuseIPDB. It's particularly useful for checking file hashes, IP addresses, or domain information.

## Features

- **VirusTotal API Integration**: Automate IP, URL/Domain and file hash queries and receive detailed analysis reports.
- **MalwareBazaar Access**: Easily check and retrieve data about various malware samples.
- **AbuseIPDB Lookup**: Quickly look up and analyze the reputation of IP addresses.
- **User-friendly Configuration**: Simple setup with API key configuration and easy-to-use functions.
- **Extensible Framework**: Designed for easy addition of more APIs or enhancement of existing functionalities.

## Getting Started

### Dependencies

- Python 3.x
- `requests` library

### Installation

1. **Clone the Repository**: 

    First, clone the repository to your local machine:

    ```bash
    git clone https://github.com/Deilis/deivscan.git
    cd deivscan
    ```

2. **Install Dependencies**:

    If you haven't installed the `requests` library, you can do so by running:

    ```bash
    pip install requests
    ```
3. **Check Requirements.txt**

   You can always run:
   ```bash
   pip install -r requirements.txt
   ```
   It will install requirements to run this script.

### Setting Up

Replace the API keys in the script with your own obtained from VirusTotal, MalwareBazaar, and AbuseIPDB.

### API Keys Configuration

The script requires API keys for VirusTotal, MalwareBazaar, and AbuseIPDB. Follow these steps to configure them:

1. **Obtain API Keys**:
   
   - Register and obtain an API key from [VirusTotal](https://www.virustotal.com/).
   - Do the same for [MalwareBazaar](https://bazaar.abuse.ch/) and [AbuseIPDB](https://www.abuseipdb.com/).

2. **Configure the Script**:

   - Open the `deivscan.py` file in a text editor.
   - Locate the lines where the API keys are set (usually at the top of the file).
   - Replace the placeholder values with your actual API keys.

### Usage

To use this tool, simply run the script with Python.
Ensure you have the necessary API keys set up in the script.

**Here is a basic example of how to run the script:**

**Script start:**

![image](https://github.com/Deilis/deivscan/assets/80956337/0ac93a57-4194-4656-8a92-96f71c7d44d1)

**Choosing option that you would like to use (for this example using Bulk IOC scan):**

![image](https://github.com/Deilis/deivscan/assets/80956337/9a8bddcc-de9a-473d-ac3f-b38d3fc66bab)

**Script runs and scans given IOCs in text file:**

![image](https://github.com/Deilis/deivscan/assets/80956337/add2c6ee-ba0e-485c-a304-89fbaa968501)
**
Output file that script provides:**

![image](https://github.com/Deilis/deivscan/assets/80956337/aabd8f0f-c66e-4786-af2a-9c8061b369ad)

### Future Improvements 

1. Improvment logging mechanisms to record the script operations.
2. Function seperation from main script.
3. Enhance error handling to manage and respod to various exceptions or API errors.
4. Integration of additional cybersecurity-related APIs to provide more comprehensive data analysis.
5. Different types of data, like threat intelligence feedds, DNS query information, SSL certificate details.
6. Implementation of asynchronus to handle multiple API requests more efficiently.
7. API managment system for API keys and other sensitive information instead of hardcoding them into the script.
8. Command-line arguments to make the script more flexible by allowing users to specify parameters and options when running script.
9. Web interface (Flask/Django) or GUI (Tkinter/PyQt)?
10. Performance optimization?

### Version History:
- V1: VirusTotal, AbuseIPDB and MalwareBazaar interaction.

### Troubleshooting
If you encounter any issues:

1. Ensure all dependencies are correctly installed.
2. Verify that the API keys are correctly set in the script.
3. Check if there are any error messages in the console and address them accordingly.

### Big thanks!
