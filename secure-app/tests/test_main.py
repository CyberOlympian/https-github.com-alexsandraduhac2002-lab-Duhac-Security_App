import io
import json
import unittest
from wsgiref.util import setup_testing_defaults

from app.main import assess_risk, application, validate_assessment_request


def invoke_app(method, path, body=None):
    environ = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = path
    payload = b""
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
    environ["wsgi.input"] = io.BytesIO(payload)
    environ["CONTENT_LENGTH"] = str(len(payload))
    environ["CONTENT_TYPE"] = "application/json"

    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    response = b"".join(application(environ, start_response)).decode("utf-8")
    return captured["status"], captured["headers"], json.loads(response)


class MainTests(unittest.TestCase):
    def test_health_endpoint(self):
        status, headers, payload = invoke_app("GET", "/health")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload, {"status": "ok"})
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_score_endpoint_returns_high_risk_for_public_unpatched_service(self):
        status, _, payload = invoke_app(
            "POST",
            "/v1/score",
            {
                "service_name": "payments-api",
                "internet_facing": True,
                "authenticated": False,
                "patch_age_days": 45,
                "data_classification": "restricted",
            },
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["service_name"], "payments-api")
        self.assertEqual(payload["risk_score"], 95)
        self.assertEqual(payload["risk_level"], "high")

    def test_invalid_json_returns_bad_request(self):
        environ = {}
        setup_testing_defaults(environ)
        environ["REQUEST_METHOD"] = "POST"
        environ["PATH_INFO"] = "/v1/score"
        environ["wsgi.input"] = io.BytesIO(b"not-json")
        environ["CONTENT_LENGTH"] = str(len(b"not-json"))
        environ["CONTENT_TYPE"] = "application/json"

        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response = b"".join(application(environ, start_response)).decode("utf-8")
        payload = json.loads(response)

        self.assertEqual(captured["status"], "400 Bad Request")
        self.assertEqual(payload["error"], "Request body must contain valid JSON.")
        self.assertEqual(captured["headers"]["Cache-Control"], "no-store")

    def test_validation_rejects_invalid_service_name(self):
        with self.assertRaises(ValueError):
            validate_assessment_request(
                {
                    "service_name": "payments api with spaces",
                    "internet_facing": True,
                    "authenticated": True,
                    "patch_age_days": 1,
                    "data_classification": "public",
                }
            )

    def test_assess_risk_grades_internal_authenticated_service_as_low(self):
        assessment = assess_risk(
            {
                "service_name": "inventory-api",
                "internet_facing": False,
                "authenticated": True,
                "patch_age_days": 2,
                "data_classification": "internal",
            }
        )
        self.assertEqual(assessment["risk_level"], "low")
        self.assertLess(assessment["risk_score"], 35)


if __name__ == "__main__":
    unittest.main()
