import requests
from api.api_keys import virus_total_api_key

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