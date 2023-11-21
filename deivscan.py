import requests 
import sys 
import os 
import time
import re

#Requests - HTTP requests to the VirusTotal API
#sys - system-specific parameters and functions
#os - way of using operating system dependend functionality
#time - various time functions

#Your VirusTotal, MalwareBazaar and AbuseIPDB API keys
virus_total_api_key = 'API_KEY_LOCATION'
malwarebazaar_api_key = 'API_KEY_LOCATION'
abuseipdb_api_key = 'API_KEY_LOCATION'


#Opens and read the file at 'file_path', exists script if file is not found
def read_file(file_path):
    try:
        with open(file_path, 'r') as f:
            print(f"Reading content from {file_path}.")
            return f.read()
    except FileNotFoundError:
        print(f"\nError: The file {file_path} was not found.")
        sys.exit(1)

#Replaces [ [.], hxxps, hxxp] with [ ., https, http] if not deweponized for submissions
def clean_input(content):
    print("\nCleaning input.")
    content = content.replace('[.]', '.')
    content = content.replace('hxxps', 'https')
    content = content.replace('hxxp', 'http')
    return content

#Replaces [ ., https, http] with [ [.], hxxps, hxxp] in output files to be deweoponized 
def sanitize_output(data):
    data = data.replace('.', '[.]')
    data = data.replace('https', 'hxxps')
    data = data.replace('http', 'hxxp')
    return data

#Writes 'data' to a file with 'file_name' and prepends a 'category' if provided
def write_to_file(file_name, data, category=None):
    sanitized_data = sanitize_output(data)
    with open(file_name, 'a') as f:
        if category:
            f.write(f"{category}:{sanitized_data}\n")
        else:
            f.write(sanitized_data + '\n')

#Prints the help text which explains briefly how to use the script.
def print_help():
    help_text = """
    Options:
        -h, --help            show this help message and exit
        1                     validate IPs from a file
        2                     validate URLs/Domains from a file
        3                     validate Hashes from a file
        4                     validate Bulk IOCs from a file
        5                     exit the script

    For Bulk IOCs:
        The script expects a text file with IOCs to be categorized and separated by a colon.
        Example:
        IPs:
        1.1.1.1
        8.8.8.8
        Hashes:
        abc123...
        def456...
        URLs/Domains:
        example.com
        anotherexample.com

    FYI.
    Script auto-weaponizes IOCs for validation and gives output files where IOCs are deweaponized.

    FYI.
    I made this script as part of Python project that I'm working on and to help my team with IOC validation.
    """
    print(help_text)

#Fetches IP Report from VirusTotal
def get_ip_report(ip):
    print(f"Fetching IP report for {ip}.")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch IP report for {ip}. Status Code: {response.status_code}")
        return None
    
def get_abuseipdb_report(ip):
    print(f"Fetching IP report in AbuseIPDB for {ip}")
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    response = requests.get(url=url, headers=headers, params=params)
   if response.status_code == 200:
        abuseipdb_response = response.json()['data']
        ip_address = abuseipdb_response.get('ipAddress', 'N/A')
        abuse_score = abuseipdb_response.get('abuseConfidenceScore', 'N/A')
        country_code = abuseipdb_response.get('countryCode', 'N/A')
        isp = abuseipdb_response.get('isp', 'N/A')
        istor = abuseipdb_response.get('isTor', 'N/A')
        total_reports = abuseipdb_response.get('totalReports', 'N/A')

        print(f"   IP: {ip_address}")
        print(f"   Abuse Score: {abuse_score}")
        print(f"   Total Reports: {total_reports}")
        print(f"   ISP: {isp}")
        print(f"   Country: {country_code}")
        print(f"   TOR IP: {istor}")

        result = (f"   Abuse Score: {abuse_score}\n   Total Reports: {total_reports}\n   Country: {country_code}\n   ISP: {isp}\n   Tor IP: {istor}\n ")
        return result
    else:
        failure_message_for_abuseipdb = f"   AbuseIPDB ha1s no information about IP {ip}\n"
        print(failure_message_for_abuseipdb)
        return failure_message_for_abuseipdb

#Fetches URL/Domain Analysis from VirusTotal
def submit_url_for_analysis(url):
    print(f"Submitting URL {url} for analysis.")
    url_endpoint = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key,
        "content-type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url_endpoint, data=payload, headers=headers)
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f"Failed to submit URL for analysis. Status Code: {response.status_code}")
        return None

#Fetches URL/Domain Report from VirusTotal with previously got url_id
def get_url_report(url_id):
    print(f"Fetching URL report for ID: {url_id}")
    url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch URL report for ID: {url_id}. Status Code: {response.status_code}")
        return None

#Fetches the Hash report from VirusTotal
def get_hash_report(hash_id):
    print(f"Fetching hash report for {hash_id}.")
    url = f"https://www.virustotal.com/api/v3/files/{hash_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        microsoft_verdict = report['data']['attributes']['last_analysis_results'].get('Microsoft', {}).get('category', 'Not Available')
        mcafee_verdict = report['data']['attributes']['last_analysis_results'].get('McAfee', {}).get('category', 'Not Available')
        microsoft_result = "Yes" if microsoft_verdict == "malicious" else "No"
        mcafee_result = "Yes" if mcafee_verdict == "malicious" else "No"
        results_vt = f"   {hash_id} Microsoft: {microsoft_result} McAfee: {mcafee_result}"
        result = f"   {hash_id} Microsoft: {microsoft_result} McAfee: {mcafee_result}"
        print(results_vt)
        return result
    else:
        failure_message_for_hash_vt = f"   Failed to fetch hash report for {hash_id}. Status Code: {response.status_code}"
        print(failure_message_for_hash_vt)
    return failure_message_for_hash_vt

def get_malwarebazaar_hash_report(hash_id):
        print(f"\nFetching hash report in MalwareBazaar for {hash_id}.")
        headers = {
            'API-KEY': malwarebazaar_api_key
        }
        data = {
            'query': 'get_info',
            'hash': hash_id,
            'key': 'links'
        }
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, headers=headers)
        if response.json()["query_status"] == 'hash_not_found':
            failure_message_for_hash_mb = f"   MalwareBazaar has no information on {hash_id}\n"
            print(failure_message_for_hash_mb)
            return failure_message_for_hash_mb

        else:
            mb_report = response.json()["data"][0]
            sha256_hash = mb_report.get("sha256_hash")
            sha1_hash = mb_report.get("sha1_hash")
            md5_hash = mb_report.get("md5_hash")
            delivery_method = mb_report.get("delivery_method")
            first_seen = mb_report.get("first_seen")
            last_seen = mb_report.get("last_seen")
            signature = mb_report.get("signature")
            tags = mb_report.get("tags")

            print(f"   SHA256 Hash: " +sha256_hash)
            print(f"   SHA1 Hash: " + sha1_hash)
            print(f"   MD5 Hash: " + md5_hash)
            print(f"   Delivery Method: " + delivery_method)
            print(f"   First Seen: " + str(first_seen))
            print(f"   Last Seen: " + str(last_seen))
            print(f"   Signature: " + signature)
            print(f"   Tags: ", tags)
            print("   MalwareBazaar URL https://bazaar.abuse.ch/sample/" + sha256_hash)
            results = f"   SHA256 Hash: {sha256_hash} \n   SHA1 Hash: {sha1_hash} \n   MD5 Hash: {md5_hash} \n   Delivery Method: {delivery_method} \n   First Seen: {first_seen} \n   Last Seen: {last_seen} \n   Signature: {signature} \n   Tags: {tags} \n   MalwareBazaar URL https://bazaar.abuse.ch/sample/{sha256_hash}\n"
            return results

        

#Provides an interactive prompt to validate different types of IOCs.
def validate_iocs():
    while True:
        print("Welcome to the VirusTotal IOC validation Python script.")
        print("Hopefully, with this script, it will be easier to validate IOCs and check if they are malicious or not.")
        print("\nWhich of the following IOCs do you want to validate:")
        print("[1] IPs")
        print("[2] URLs/Domains")
        print("[3] Hashes")
        print("[4] Bulk IOCs")
        print("[5] Exit script")
        print("[-h]/[--help] Help")
        choice = input("Choose an option 1, 2, 3, 4, 5 for validation, as well you can choose -h or --help for more information.\nYour choice: ")

        if choice.lower() in ['-h', '--help']:
            print_help()
            continue 
        elif choice in ['1', '2', '3', '4', '5']:
            return choice 
        else:
            print("\nInvalid option, please select again.")

#File parser and regex expressions to check for IOCs
def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) is not None

def is_url(s):
    return re.match(r"(https?://)?[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+", s) is not None

def is_hash(s):
    return re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", s) is not None

#Parses the bulk IOCs from a given string 'content'.
def parse_bulk_iocs(content):
    iocs = {'ips': [], 'urls': [], 'hashes': []}
    for line in content.splitlines():
        line = line.strip()
        if line:
            if is_ip(line):
                iocs['ips'].append(line)
            elif is_url(line):
                iocs['urls'].append(line)
            elif is_hash(line):
                iocs['hashes'].append(line)
            else:
                print(f"Sorry we were unable to recognize IOC format: {line}")
    return iocs

#Performs analysis on bulk IOCs and writes the results to 'output_file_path'.
def bulk_analysis(iocs, output_file_path):
    if iocs['ips']:
        write_to_file(output_file_path, "", category="IPs")
        print("\nScanning IPs.")
        for ip in iocs['ips']:
            print(f"\nScanning IP: {ip}")
            report_vt_ip = get_ip_report(ip)
            report_abuseipdb = get_abuseipdb_report(ip)
            combined_report = f"VirusTotal Report:\n{report_vt_ip}\nAbuseIPDB Report:\n{report_abuseipdb}"
            write_to_file(output_file_path, combined_report)

    if iocs['urls']:
        write_to_file(output_file_path, "", category="URLs/Domains")
        print("\nScanning URLs/Domains.")
        for url in iocs['urls']:
            print(f"\nScanning URL/Domain: {url}")
            url_id = submit_url_for_analysis(url)
            if url_id:
                time.sleep(16)  # Sleep 15 seconds between submissions to avoid exceeding rate limits
                report = get_url_report(url_id)
                write_to_file(output_file_path, report)

    if iocs['hashes']:
        write_to_file(output_file_path, "", category="Hashes")
        print("\nScanning Hashes.")
        for hash_id in iocs['hashes']:
            print(f"\nScanning Hash: {hash_id}")
            report_vt = get_hash_report(hash_id)
            report_mb = get_malwarebazaar_hash_report(hash_id)
            combined_report = f"VirusTotal Report:\n{report_vt}\nMalwareBazaar Report:\n{report_mb}"
            write_to_file(output_file_path, combined_report)

#Processes a file containing IOCs of a specific 'category'.
def process_individual_ioc_file(file_path, category):
    content = read_file(file_path)
    cleaned_content = clean_input(content)
    iocs = {category: cleaned_content.splitlines()}
    return iocs

#Extended version of bulk_analysis, handles individual IOCs as well.
def perform_bulk_analysis(iocs, output_file_path):
    # The perform_bulk_analysis function is refactored to also handle individual IOC file analysis.
    for category, entries in iocs.items():
        if entries:
            write_to_file(output_file_path, "", category=category.capitalize())
            if category == 'ips':
                print("\nScanning IPs.")
                for ip in entries:
                    print(f"\nScanning IP: {ip}")
                    report_vt_ip = get_ip_report(ip)
                    if report_vt_ip:
                        malicious_score = report_vt_ip['data']['attributes']['last_analysis_stats']['malicious']
                        total_score = sum(report_vt_ip['data']['attributes']['last_analysis_stats'].values())
                        vt_result = f"   {ip} Malicious {malicious_score}/{total_score} Vendor Score"
                        print(vt_result)
                        write_to_file(output_file_path, vt_result)
                    report_abuseipdb = get_abuseipdb_report(ip)
                    if report_abuseipdb:
                        write_to_file(output_file_path, report_abuseipdb)
                    time.sleep(16)
            elif category == 'urls':
                print("\nScanning URLs/Domains.")
                for url in entries:
                    print(f"\nScanning URL/Domain: {url}")
                    url_id = submit_url_for_analysis(url)
                    if url_id:
                        time.sleep(16)  # Wait for URL analysis to complete
                        report = get_url_report(url_id)
                        if report:
                            result = f"   {url} Malicious {report['data']['attributes']['stats']['malicious']}/{sum(report['data']['attributes']['stats'].values())} Vendor Score\n"
                            write_to_file(output_file_path, result)
                            print(result)
                    time.sleep(16)
            elif category == 'hashes':
                print("\nScanning Hashes.")
                for hash_id in entries:
                    print(f"\nScanning Hash: {hash_id}")
                    report_vt = get_hash_report(hash_id)
                    report_mb = get_malwarebazaar_hash_report(hash_id)
                    if report_vt:
                        write_to_file(output_file_path, report_vt)
                    if report_mb:
                        write_to_file(output_file_path, report_mb)
                    time.sleep(16)

#Main function which controls the script flow, starting point of the script.
def main():
    script_directory = os.path.dirname(os.path.realpath(__file__))
    show_help = False

    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        show_help = True

    while True:
        if show_help:
            print_help()
            show_help = False  
            continue  

        choice = validate_iocs()

        if choice is None:
            continue

        if choice == '5':
            sys.exit("\nExiting script.")

        if choice == '4':
            file_name = input('Please provide the name of the txt file for Bulk IOCs (located in the same folder as this script): ')
            output_file_name = input('Please provide the name of the output file for Bulk IOC results: ')
            file_path = os.path.join(script_directory, file_name)
            output_file_path = os.path.join(script_directory, output_file_name)
            content = read_file(file_path)
            cleaned_content = clean_input(content)
            iocs = parse_bulk_iocs(cleaned_content)
            perform_bulk_analysis(iocs, output_file_path)

        elif choice in ['1', '2', '3']:
            ioc_type = {'1': 'ips', '2': 'urls', '3': 'hashes'}[choice]
            file_name = input(f'Please provide the name of the txt file for {ioc_type.upper()} (located in the same folder as this script): ')
            output_file_name = input('Please provide the name of the output file for IOC results: ')
            file_path = os.path.join(script_directory, file_name)
            output_file_path = os.path.join(script_directory, output_file_name)
            iocs = process_individual_ioc_file(file_path, ioc_type)
            perform_bulk_analysis(iocs, output_file_path)

        else:
            print("\nInvalid option, please select again.")

if __name__ == "__main__":
    main()