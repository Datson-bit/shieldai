from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch

class EmailAnalysisTests(TestCase):
    def test_analyse_email_no_content(self):
        url = reverse("analyse-email")
        response = self.client.post(url, data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    @patch("scanner.views.analyse_email_with_gemini")
    def test_analyse_email_success(self, mock_analyse):
        mock_analyse.return_value = {
            "status": "SUCCESS",
            "verdict": "Phishing Attempt",
            "risk_score": 85,
            "flags": ["Urgent language", "OPay spoofing"],
            "summary": "This email is suspicious."
        }
        url = reverse("analyse-email")
        response = self.client.post(url, data={"email_content": "Dear customer, click link"})
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["verdict"], "Phishing Attempt")
        self.assertEqual(data["risk_score"], 85)

