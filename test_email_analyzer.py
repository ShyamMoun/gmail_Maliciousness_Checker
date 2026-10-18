
import unittest
from email_analyzer import analyze_email


class TestEmailAnalyzer(unittest.TestCase):

    def test_normal_email_has_no_findings(self):
        result = analyze_email(
            "friend@example.com",
            "Meeting tomorrow",
            "Hello, see you at the meeting tomorrow."
        )
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["score"], 0)

    def test_urgent_phrase_is_flagged(self):
        result = analyze_email(
            "alerts@example.com",
            "Account notice",
            "Please verify your account immediately."
        )
        self.assertGreater(result["score"], 0)
        self.assertTrue(result["findings"])

    def test_http_url_is_flagged(self):
        result = analyze_email(
            "alerts@example.com",
            "Website",
            "Visit http://example.com/login"
        )
        self.assertGreater(result["score"], 0)
        self.assertEqual(result["url_count"], 1)

    def test_embedded_credentials_are_flagged(self):
        result = analyze_email(
            "alerts@example.com",
            "Link",
            "Visit http://user:pass@example.com/login"
        )
        self.assertTrue(
            any("embedded credentials" in item.lower()
                for item in result["findings"])
        )


if __name__ == "__main__":
    unittest.main()
