import sys
import os
from utils.common_utils import print_help
from ioc_processing.ioc_functions import (
    validate_iocs,
    parse_bulk_iocs,
    bulk_analysis,
    process_individual_ioc_file,
    perform_bulk_analysis
)
from file_operations.file_utils import (
    read_file,
    clean_input
)

def main():
    script_directory = os.path.dirname(os.path.realpath(__file__))
    input_directory = os.path.join(script_directory, 'input_files')
    output_directory = os.path.join(script_directory, 'output_files')
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
            file_name = input('Please provide the name of the txt file for Bulk IOCs: ')
            output_file_name = input('Please provide the name of the output file for Bulk IOC results: ')
            file_path = os.path.join(input_directory, file_name)
            output_file_path = os.path.join(output_directory, output_file_name)
            content = read_file(file_name)
            cleaned_content = clean_input(content)
            iocs = parse_bulk_iocs(cleaned_content)
            perform_bulk_analysis(iocs, output_file_path)

        elif choice in ['1', '2', '3']:
            ioc_type = {'1': 'ips', '2': 'urls', '3': 'hashes'}[choice]
            file_name = input(f'Please provide the name of the txt file for {ioc_type.upper()}: ')
            output_file_name = input('Please provide the name of the output file for IOC results: ')
            file_path = os.path.join(input_directory, file_name)
            output_file_path = os.path.join(output_directory, output_file_name)
            iocs = process_individual_ioc_file(file_name, ioc_type)
            perform_bulk_analysis(iocs, output_file_path)

        else:
            print("\nInvalid option, please select again.")

if __name__ == "__main__":
    main()