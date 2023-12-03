import os
import sys
import unittest
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from file_operations.file_utils import clean_input
from ioc_processing.ioc_functions import bulk_analysis

class TestIOCValidator(unittest.TestCase):

#Testing clean_input function if it's removing port numbers
    def test_clean_input(self):
        dirty_input = "43.133.136.161:4850"
        expected_output = "43.133.136.161"
        self.assertEqual(clean_input(dirty_input), expected_output)

    @patch('ioc_processing.ioc_functions.get_ip_report')
    @patch('ioc_processing.ioc_functions.submit_url_for_analysis')
    @patch('ioc_processing.ioc_functions.get_url_report')
    @patch('ioc_processing.ioc_functions.get_hash_report')

    def test_bulk_analysis(self, mock_get_hash_report, mock_get_url_report, mock_submit_url_for_analysis, mock_get_ip_report):
        mock_get_ip_report.return_value = {'status': 'success'}
        mock_submit_url_for_analysis.return_value = {'status': 'success'}
        mock_get_url_report.return_value = {'status': 'success'}
        mock_get_hash_report.return_value = {'status': 'success'}

        iocs = {
            'ips': ['8.8.8.8'],
            'urls': ['http://example.com'],
            'hashes': ['44d88612fea8a8f36de82e1278abb02f']
        }

        output_file_path = 'test_output.txt'
        bulk_analysis(iocs, output_file_path)

        mock_get_ip_report.assert_called_once()
        mock_submit_url_for_analysis.assert_called_once()
        mock_get_url_report.assert_called_once()
        mock_get_hash_report.assert_called_once()

if __name__ == '__main__':
    unittest.main()