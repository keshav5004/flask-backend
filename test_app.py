import unittest
import json
import os
import shutil
from app import app, CSV_PATH


class TestWebsiteSafetyChecker(unittest.TestCase):
    def setUp(self):
        # Configure the Flask app for testing
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_safe_url(self):
        """
        Test that a domain NOT in the CSV blacklist returns a safe status.
        """
        response = self.client.post(
            '/scan',
            data=json.dumps({"url": "https://google.com/search?q=flask"}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'safe')
        self.assertTrue(data['safe'])
        self.assertIn('clean', data['message'].lower())

    def test_malicious_url_full_match(self):
        """
        Test that a domain in the CSV blacklist returns a malicious status.
        Uses normalization.
        """
        # "nobell.it" is in the CSV. Let's test with subdirectories and scheme.
        response = self.client.post(
            '/scan',
            data=json.dumps({"url": "https://www.nobell.it/some/path?id=danger"}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'malicious')
        self.assertFalse(data['safe'])
        self.assertIn('blacklist', data['message'].lower())

    def test_malicious_url_simple_match(self):
        """
        Test checking raw domain string.
        """
        response = self.client.post(
            '/scan',
            data=json.dumps({"url": "dghjdgf.com"}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'malicious')
    def test_api_check_suspicious(self):
        """
        Test the GET /api/check endpoint for a suspicious lookalike URL using new TLDs/keywords.
        """
        response = self.client.get('/api/check?url=test-paypal-billing-verify.vip')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'malicious')
        self.assertFalse(data['safe'])
        self.assertGreaterEqual(data['risk_score'], 40)
        self.assertEqual(data['detection_method'], 'similarity_analysis')

    def test_missing_url_field(self):
        """
        Test that omitting the 'url' field returns a 400 Bad Request.
        """
        response = self.client.post(
            '/scan',
            data=json.dumps({}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Bad Request')

    def test_non_string_url(self):
        """
        Test that providing a non-string 'url' value returns a 400 Bad Request.
        """
        response = self.client.post(
            '/scan',
            data=json.dumps({"url": 12345}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('error', data)

    def test_invalid_json(self):
        """
        Test that posting raw malformed JSON content type returns a 400 Bad Request.
        """
        response = self.client.post(
            '/scan',
            data="{invalid-json-structure",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('error', data)

    def test_missing_dataset_file(self):
        """
        Test that if the CSV database is missing, the API returns a 500 status code with a JSON error.
        We simulate this by renaming the CSV file temporarily, reloading the module, and checking the endpoint.
        """
        temp_backup = CSV_PATH + ".bak"
        
        # Rename the dataset to simulate file loss
        if os.path.exists(CSV_PATH):
            shutil.move(CSV_PATH, temp_backup)
            
        try:
            # Force re-initialization error
            import app as flask_app
            flask_app.init_error = FileNotFoundError("CSV file is missing")
            
            # Request scan
            response = self.client.post(
                '/scan',
                data=json.dumps({"url": "example.com"}),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 500)
            data = response.get_json()
            self.assertEqual(data['error'], 'Dataset Missing')
            self.assertIn('CSV dataset file is missing', data['message'])
            
        finally:
            # Restore the file
            if os.path.exists(temp_backup):
                shutil.move(temp_backup, CSV_PATH)
            
            # Reset init error state
            import app as flask_app
            flask_app.init_error = None
            try:
                from services.checker import CSVBlacklistChecker
                flask_app.checker = CSVBlacklistChecker(CSV_PATH)
            except Exception as e:
                flask_app.init_error = e


if __name__ == '__main__':
    unittest.main()
