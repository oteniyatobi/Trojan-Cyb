import json
import os
import unittest
from unittest.mock import MagicMock, patch

from groq_review import check_review, get_review


class GroqReviewRetryTests(unittest.TestCase):
    @patch("groq_review.time.sleep")
    @patch("groq_review.requests.post")
    def test_rate_limit_retries_after_provider_delay(self, post, sleep):
        limited = MagicMock(status_code=429, headers={"Retry-After": "4"})
        success = MagicMock(status_code=200)
        success.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "attack_type": "Other",
                        "severity": "low",
                        "headline": "Test",
                        "what_happened": "Test.",
                        "why_it_matters": "Test.",
                        "steps": ["Review the alert."],
                        "when_to_escalate": "If it continues.",
                    }),
                },
            }],
        }
        post.side_effect = [limited, success]

        with patch.dict(os.environ, {
            "GROQ_API_KEY": "test-key",
            "GROQ_MAX_RETRIES": "2",
            "GROQ_TIMEOUT_SECONDS": "7",
        }):
            review = get_review("test alert")

        self.assertEqual(review["headline"], "Test")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args.kwargs["timeout"], 7)
        sleep.assert_called_once_with(4)


if __name__ == "__main__":
    unittest.main()


def good_review(**changes):
    review = {
        "attack_type": "Other",
        "severity": "medium",
        "headline": "Test",
        "what_happened": "Test.",
        "why_it_matters": "Test.",
        "steps": ["Review the alert."],
        "when_to_escalate": "If it continues.",
    }
    review.update(changes)
    return review


class CheckReviewTests(unittest.TestCase):
    def test_valid_review_passes(self):
        self.assertEqual(check_review(good_review()), [])

    def test_fixes_case_and_single_step(self):
        review = good_review(severity=" High ", attack_type="other", steps="Block the address.")
        self.assertEqual(check_review(review), [])
        self.assertEqual((review["severity"], review["attack_type"], review["steps"]),
                         ("high", "Other", ["Block the address."]))

    def test_rejects_unknown_values_and_empty_text(self):
        problems = check_review(good_review(severity="urgent", attack_type="Aliens", headline=" ", steps=[]))
        self.assertEqual(len(problems), 4)

    def test_rejects_missing_keys_and_non_objects(self):
        self.assertTrue(check_review({"severity": "low"})[0].startswith("Missing keys"))
        self.assertEqual(check_review(["not", "a", "dict"]), ["Review is not a JSON object"])
