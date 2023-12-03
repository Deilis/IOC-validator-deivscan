import time
from utils.common_utils import print_help
from api_interactions.malwarebazaar import get_malwarebazaar_hash_report
from api_interactions.abuseipdb import get_abuseipdb_report
from file_operations.file_utils import (
    is_ip,
    is_url,
    is_hash,
    read_file,
    write_to_file,
    clean_input
)
from api_interactions.virustotal import (
    get_ip_report,
    submit_url_for_analysis,
    get_url_report,
    get_hash_report
)

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
                for count, ip in enumerate(entries, start=1):
                    print(f"\nScanning IP [{count}/{len(entries)}]: {ip}")
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
                for count, url in enumerate(entries, start=1):
                    print(f"\nScanning URL/Domain [{count}/{len(entries)}]: {url}")
                    url_id = submit_url_for_analysis(url)
                    if url_id:
                        time.sleep(16)  # Wait for URL analysis to complete
                        report = get_url_report(url_id)
                        if report:
                            result = f"   {url} Malicious {report['data']['attributes']['stats']['malicious']}/{sum(report['data']['attributes']['stats'].values())} Vendor Score"
                            write_to_file(output_file_path, result)
                            print(result)
                    time.sleep(16)
            elif category == 'hashes':
                print("\nScanning Hashes.")
                for count, hash_id in enumerate(entries, start=1):
                    print(f"\nScanning Hash [{count}/{len(entries)}]: {hash_id}")
                    report_vt = get_hash_report(hash_id)
                    report_mb = get_malwarebazaar_hash_report(hash_id)
                    if report_vt:
                        write_to_file(output_file_path, report_vt)
                    if report_mb:
                        write_to_file(output_file_path, report_mb)
                    time.sleep(16)