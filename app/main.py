"""Secure, dependency-free microservice for DevSecOps demos."""
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

MAX_REQUEST_BODY_BYTES = 4096
ALLOWED_CLASSIFICATIONS = {"public", "internal", "restricted"}


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _response(start_response, status: HTTPStatus, payload: dict[str, Any], extra_headers: list[tuple[str, str]] | None = None):
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(f"{status.value} {status.phrase}", headers)
    return [_json_bytes(payload)]


def _error(start_response, status: HTTPStatus, message: str):
    return _response(start_response, status, {"error": message})


def _read_body(environ: dict[str, Any]) -> bytes:
    content_length_raw = environ.get("CONTENT_LENGTH") or "0"
    try:
        content_length = int(content_length_raw)
    except ValueError as exc:
        raise ValueError("Invalid Content-Length header.") from exc

    if content_length < 0:
        raise ValueError("Request body is invalid.")
    if content_length > MAX_REQUEST_BODY_BYTES:
        raise ValueError("Request body is too large.")

    body = environ["wsgi.input"].read(content_length)
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise ValueError("Request body is too large.")
    return body


def _load_json_payload(environ: dict[str, Any]) -> dict[str, Any]:
    body = _read_body(environ)
    if not body:
        raise ValueError("A JSON payload is required.")

    try:
        payload = json.loads(body.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("Request body must be UTF-8 encoded JSON.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Request body must contain valid JSON.") from exc

    if not isinstance(payload, dict):
        raise ValueError("The JSON payload must be an object.")
    return payload


def _normalize_service_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("'service_name' must be a string.")

    service_name = value.strip()
    if not service_name:
        raise ValueError("'service_name' is required.")
    if len(service_name) > 64:
        raise ValueError("'service_name' must not exceed 64 characters.")
    if not all(character.isalnum() or character in {"-", "_"} for character in service_name):
        raise ValueError("'service_name' may only contain letters, numbers, hyphens, and underscores.")
    return service_name


def _normalize_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"'{field_name}' must be a boolean.")


def _normalize_patch_age(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("'patch_age_days' must be an integer.")
    if value < 0 or value > 3650:
        raise ValueError("'patch_age_days' must be between 0 and 3650.")
    return value


def _normalize_classification(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("'data_classification' must be a string.")

    classification = value.strip().lower()
    if classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError("'data_classification' must be one of: public, internal, restricted.")
    return classification


def validate_assessment_request(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": _normalize_service_name(payload.get("service_name")),
        "internet_facing": _normalize_bool(payload.get("internet_facing"), "internet_facing"),
        "authenticated": _normalize_bool(payload.get("authenticated"), "authenticated"),
        "patch_age_days": _normalize_patch_age(payload.get("patch_age_days")),
        "data_classification": _normalize_classification(payload.get("data_classification")),
    }


def assess_risk(request_data: dict[str, Any]) -> dict[str, Any]:
    score = 0
    if request_data["internet_facing"]:
        score += 35
    if request_data["authenticated"]:
        score -= 10
    else:
        score += 20

    patch_age_days = request_data["patch_age_days"]
    if patch_age_days >= 30:
        score += 25
    elif patch_age_days >= 7:
        score += 10

    classification = request_data["data_classification"]
    if classification == "internal":
        score += 5
    elif classification == "restricted":
        score += 15

    score = max(0, min(score, 100))
    if score < 35:
        level = "low"
        recommendation = "Maintain current controls and keep monitoring."
    elif score < 70:
        level = "moderate"
        recommendation = "Review exposure, refresh patches, and tighten access."
    else:
        level = "high"
        recommendation = "Prioritize hardening work before release."

    return {
        "service_name": request_data["service_name"],
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation,
    }


def application(environ: dict[str, Any], start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "/")

    if method == "GET" and path == "/health":
        return _response(start_response, HTTPStatus.OK, {"status": "ok"})

    if method == "POST" and path == "/v1/score":
        try:
            payload = _load_json_payload(environ)
            validated = validate_assessment_request(payload)
            assessment = assess_risk(validated)
        except ValueError as exc:
            return _error(start_response, HTTPStatus.BAD_REQUEST, str(exc))
        return _response(start_response, HTTPStatus.OK, assessment)

    if path in {"/health", "/v1/score"}:
        allow_header = "GET" if path == "/health" else "POST"
        return _response(start_response, HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method not allowed."}, [("Allow", allow_header)])

    return _error(start_response, HTTPStatus.NOT_FOUND, "Not found.")


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - inherited signature
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the secure demo microservice.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address for the HTTP server.")
    parser.add_argument("--port", default=8080, type=int, help="Port for the HTTP server.")
    args = parser.parse_args()

    with make_server(args.host, args.port, application, server_class=WSGIServer, handler_class=QuietHandler) as httpd:
        print(f"Serving on http://{args.host}:{args.port}")
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())