import unittest
from unittest.mock import patch, MagicMock
import deivscan  

#THIS IS TEST SCRIPT, THIS IS NOT ACTUAL TEST.PY FOR MY SCRIPT, TRYING TO MOCK SOMETHING UP.

class TestAPIScript(unittest.TestCase):

    def setUp(self):
     
        pass

    @patch('your_script_name.requests.get')
    def test_virus_total_api_call_success(self, mock_get):
        #Mock successful API response
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"response": "success"})
        response = deivscan.query_virus_total("test_query")
        self.assertEqual(response, {"response": "success"})
    @patch('deivscan.requests.get')
  
    def test_malwarebazaar_api_call_success(self, mock_get):
        #Mock successful API response
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"response": "success"})
        response = your_script_name.query_malwarebazaar("test_query")
        self.assertEqual(response, {"response": "success"})
    @patch('deivscan.requests.get')
  
    def test_abuseipdb_api_call_success(self, mock_get):
        #Mock successful API response
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"response": "success"})
        response = your_script_name.query_abuseipdb("test_query")
        #Assertions
        self.assertEqual(response, {"response": "success"})

    #Needs to add more tests as needed for different scenarios and functions

if __name__ == '__main__':
    unittest.main()
