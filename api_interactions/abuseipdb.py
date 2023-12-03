import requests
from api.api_keys import abuseipdb_api_key

#Fetches AbuseIPDB report for IP
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