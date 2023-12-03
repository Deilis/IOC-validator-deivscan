# Description

This Python script is designed for security analysts, researchers, and enthusiasts, facilitating automated interactions with multiple cybersecurity APIs including VirusTotal, MalwareBazaar, and AbuseIPDB. The tool automates the process of sending HTTP requests to these platforms, handling requests and responses effectively. It is particularly useful for quickly gathering and analyzing data related to file hashes, IP addresses, or domain information, thereby streamlining tasks in cybersecurity analysis and research.

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Setting Up](#setting-up)
  - [API Keys Configuration](#api-keys-configuration)
- [Usage](#usage)
- [Future Improvements](#future-improvements)
- [Version History](#version-history)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Flow Chart](#flow-chart)
- [Big thanks!](#big-thanks)

## Features

- **VirusTotal API Integration**: Automate IP, URL/Domain and file hash queries and receive detailed analysis reports.
- **MalwareBazaar Access**: Easily check and retrieve data about various malware samples.
- **AbuseIPDB Lookup**: Quickly look up and analyze the reputation of IP addresses.
- **User-friendly Configuration**: Simple setup with API key configuration and easy-to-use functions.
- **Extensible Framework**: Designed for easy addition of more APIs or enhancement of existing functionalities.
- **Modular Design**: Functions are now separated into different modules for better maintainability and scalability. [12/03/2023]
- **Input Sanitization**: Enhanced input processing to remove unnecessary port numbers and other artifacts. [12/03/2023]

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

Replace the API keys in the `api/api_keys.py`  with your own obtained from VirusTotal, MalwareBazaar, and AbuseIPDB.

### API Keys Configuration

The script requires API keys for VirusTotal, MalwareBazaar, and AbuseIPDB. Follow these steps to configure them:

1. **Obtain API Keys**:
   
   - Register and obtain an API key from [VirusTotal](https://www.virustotal.com/).
   - Do the same for [MalwareBazaar](https://bazaar.abuse.ch/) and [AbuseIPDB](https://www.abuseipdb.com/).

2. **Configure the Script**:

   - Open the `api/api_keys.py` file in a text editor.
   - First three lines are for API keys [VirusTotal, MalwareBazaar and AbuseiPDB].
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

## Future Improvements 

## Future Improvements 

- [ ] Implement logging mechanisms to record the script operations for better traceability and debugging.
- [x] Separate functions from the main script into modules for improved maintainability. **[Completed 12/03/2023]**
- [x] Enhance error handling to manage and respond to various exceptions or API errors more gracefully. **[Completed 12/03/2023]**
- [ ] Integrate additional cybersecurity-related APIs to provide more comprehensive data analysis. **[Searching for reliable Vendors]**
- [ ] Add support for different types of data, like threat intelligence feeds, DNS query information, and SSL certificate details.
- [ ] Implement asynchronous handling to manage multiple API requests more efficiently.
- [x] Develop an API management system for API keys and other sensitive information to avoid hardcoding them into the script. **[Parly Completed 12/03/2023]**
- [ ] Enable command-line arguments to make the script more flexible by allowing users to specify parameters and options when running the script. **[Ongoing]**
- [ ] Explore the development of a web interface (Flask/Django) or GUI (Tkinter/PyQt) to make the tool more accessible to users who prefer graphical interfaces.
- [ ] Optimize performance to handle large volumes of IOCs with minimal latency.
- [ ] CSV file output by users choice.
- [x] Input sanitization to remove unnecessary port numbers and other artifacts. **[Completed 12/03/2023]**

## Version History:
**V1  : [11/19/2023]:**

VirusTotal, AbuseIPDB and MalwareBazaar interaction.

**V1.1: [11/21/2023]:**

Updated Error from AbuseIPDB when variable `country_code` is `None`. Error was happening because responses was not containing `country_code` since some of the IPs that I was querring was private and had no associated country information. Modification was made to give out default value of `N/A` if the `country_code` (or any other field) is not presented in the response, thus preventing the script from attempting to concatenate `None` with a string.

Added a counter in terminal to display which IOC is currently being validated from given IOCs with `enumerate` function in Python. Modification `enumerate` was used to iterate over each category of IOCs, and `count` is the counter that keeps track of the current number of IOCs being processed. `start=1` argument ensures that counting starts from 1 instead of default 0. The `len(entries)` part was used to display the total number of IOCs in the current `category` being processed.

Added expressions for IPs, URLs/Domains and Hashes so if there's no IOC naming it would check IOCs using regex functions `def is_ip` (simple IP address regex), `def_is_url` (URL regex pattern to match various URL formats) and `def is_hash` (Hash regex for common hash formats SHA1, SHA256, MD5) 

**V1.2: [12/03/2023]**

Implemented a modular design by seperating functions into different modules, enhancing code maintainability and scalability.

Added input sanitization features to strip port numbers from IP addresses and URLs/Domains to ensure correct data formating for API requests.

Improved error handling across the script to provide clearer debugging information.

Enhanced the user experience by providing a more interactive prompt and clearer instructions for usage.

Refactored code to impove performance and readability.

Added `project_test/test_script.py` to test script, output of testing is in `output_files`.

## Troubleshooting
Encountering issues? Here's how to troubleshoot common problems:

- API Key Authentication: If you receive a "Status Code: 401" error, this typically means there's an issue with your API keys. Double-check that they are correctly entered in api/api_keys.py and have the necessary permissions.
- Installation Issues: Make sure all dependencies are correctly installed by running pip install -r requirements.txt.
- Runtime Errors: If the script exits unexpectedly or provides incorrect results, review the console output for error messages. This can often lead to a quick resolution.

1. Ensure all dependencies are correctly installed.
2. Verify that the API keys are correctly set in the script.
3. Check if there are any error messages in the console and address them accordingly.

## Testing

For testing check `project_tests/test_script.py`, output is given in `output_files/test_output.txt`

## Flow Chart

![image](https://github.com/Deilis/IOC-validator-deivscan/assets/80956337/63306aa4-43a4-4361-960e-ed05d89d0d3b)

## Big thanks!
