import sys
import re
import os
import json

#Makes sure that directories input_files and output_files are created, if not creates them
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

#Opens and read the file at 'file_path', exists script if file is not found
def read_file(file_name):
    input_directory = os.path.join(os.path.dirname(__file__), '..', 'input_files')
    ensure_directory_exists(input_directory)
    file_path = os.path.join(input_directory, file_name)
    try:
        with open(file_path, 'r') as f:
            print(f'Reading content from {file_path}.')
            return f.read()
    except FileNotFoundError:
        print(f'\nError: The file {file_path} was not found, check again.')
        sys.exit(1)

#Writes 'data' to a file with 'file_name' and prepends a 'category' if provided
def write_to_file(file_name, data, category=None):
    output_directory = os.path.join(os.path.dirname(__file__), '..', 'output_files')
    file_path = os.path.join(output_directory, file_name)
    ensure_directory_exists(output_directory)

    if isinstance(data, dict):
        data = json.dumps(data, indent=4)

    sanitized_data = sanitize_output(data)
    with open(file_path, 'a') as f:
        if category:
            f.write(f'{category}:{sanitized_data}\n')
        else:
            f.write(sanitized_data + '\n')       

#Replaces [ [.], hxxps, hxxp] with [ ., https, http] if not deweponized for submissions
#Added regex to remove port numbers
def clean_input(content):
    print('\nCleaning input.')
    content = content.replace('[.]', '.')
    content = content.replace('hxxp', 'http')
    content = content.replace('hxxps', 'https')
    content = re.sub(r':\d+/?', '', content) 
    return content

#Replaces [ ., https, http] with [ [.], hxxps, hxxp] in output files to be deweoponized 
def sanitize_output(data):
    if not isinstance(data, dict) and not data.startswith('{'):
        data = data.replace('.', '[.]')
        data = data.replace('http', 'hxxp')
        data = data.replace('https', 'hxxps')
    return data

#File parser and regex expressions to check for IOCs
def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) is not None

def is_url(s):
    return re.match(r"(https?://)?[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+", s) is not None

def is_hash(s):
    return re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", s) is not None