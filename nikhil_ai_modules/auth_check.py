"""Authentication/session review with optional one-shot, approved test-account login."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlsplit

from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.evidence import sanitize_url
from nikhil_ai_modules.cookies import _set_cookie_headers, analyze_cookies
from nikhil_ai_modules.output import header, info, section, warn
from nikhil_ai_modules.parsers import parse_page
from nikhil_ai_modules.scope import ScopeError, normalize_url


def _cookie_names(response):
    try:
        return sorted(cookie.name for cookie in response.cookies)
    except Exception:
        return []


def _cookie_snapshot(response):
    """Return transient value hashes; never persist or expose cookie contents."""
    try:
        return {cookie.name: hashlib.sha256(cookie.value.encode("utf-8", errors="replace")).digest()
                for cookie in response.cookies}
    except Exception:
        return {}


def _rate_headers(headers):
    return {key: value for key, value in headers.items() if key.lower() in {"retry-after", "ratelimit-limit", "ratelimit-remaining", "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit"}}


def analyze_authentication(
    target,
    context=None,
    *,
    test_login: bool = False,
    confirm_login: bool = False,
    credentials=None,
):
    ctx = resolve_context(context)
    url = normalize_url(target)
    response = ctx.http.get(url)
    page = parse_page(response.text)
    password_forms = [form for form in page.forms if any(field["type"] == "password" for field in form["fields"])]
    login_form = password_forms[0] if password_forms else None
    form_action = urljoin(response.url, login_form["action"] or response.url) if login_form else None
    form_summary = []
    for form in page.forms:
        form_summary.append({
            "action": sanitize_url(normalize_url(urljoin(response.url, form["action"] or response.url))),
            "method": form["method"],
            "field_names": [field["name"] for field in form["fields"] if field.get("name")],
            "has_password": any(field["type"] == "password" for field in form["fields"]),
        })
    initial_cookie_names = _cookie_names(response)
    initial_cookie_snapshot = _cookie_snapshot(response)
    cookie_review = analyze_cookies(_set_cookie_headers(response), response.url)
    login_result = None

    if test_login:
        if not confirm_login:
            raise ScopeError("A login POST requires explicit confirmation for a researcher-controlled test account")
        if not credentials or not credentials.get("username") or not credentials.get("password"):
            raise ValueError("A one-shot login test requires both test-account username and password")
        if not login_form or not form_action:
            raise ValueError("No password form was found on the supplied URL")
        if login_form["method"] != "POST":
            raise ScopeError("Safe login test only supports a POST form; credentials will not be put in a URL")
        fields = login_form["fields"]
        password_field = next((field["name"] for field in fields if field["type"] == "password" and field.get("name")), None)
        username_field = next((field["name"] for field in fields if field.get("name") and field["type"] in ("text", "email") and re.search(r"user|email|login", field["name"], re.I)), None)
        if not username_field:
            username_field = next((field["name"] for field in fields if field.get("name") and field["type"] in ("text", "email")), None)
        if not username_field or not password_field:
            raise ValueError("Could not identify username/password form fields safely")
        payload = {field["name"]: field.get("value", "") for field in fields if field.get("name") and field["type"] == "hidden"}
        payload[username_field] = str(credentials["username"])
        payload[password_field] = str(credentials["password"])
        cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in response.cookies)
        headers = {"Referer": response.url}
        if cookie_header:
            headers["Cookie"] = cookie_header
        # This is the only write-capable auth flow: one POST, only after an
        # explicit CLI confirmation and only to a form action in authorized scope.
        login_response = ctx.http.post(form_action, data=payload, headers=headers, allow_post=True)
        response_text = login_response.text[:100000].lower()
        login_result = {
            "status_code": login_response.status_code,
            "cookie_names_before": initial_cookie_names,
            "cookie_names_after": _cookie_names(login_response),
            "session_cookie_name_set_changed": set(initial_cookie_names) != set(_cookie_names(login_response)),
            "session_cookie_values_changed": initial_cookie_snapshot != _cookie_snapshot(login_response),
            "rate_limit_headers": _rate_headers(login_response.headers),
            "generic_auth_error_observed": any(text in response_text for text in ("invalid credentials", "incorrect password", "authentication failed", "try again")),
            "credentials_sent": True,
        }
        cookie_review.extend(analyze_cookies(_set_cookie_headers(login_response), login_response.url))

    logout_refs = []
    for link in page.links:
        candidate = urljoin(response.url, link)
        if "logout" in urlsplit(candidate).path.lower() and ctx.scope.is_in_scope(urlsplit(candidate).hostname or ""):
            logout_refs.append(sanitize_url(candidate))
    result = {
        "target": sanitize_url(response.url),
        "status_code": response.status_code,
        "login_forms": form_summary,
        "session_cookies": cookie_review,
        "rate_limit_headers": _rate_headers(response.headers),
        "logout_references": list(dict.fromkeys(logout_refs)),
        "logout_behavior_tested": False,
        "login_test": login_result,
        "manual_steps": [
            "Verify session identifier rotation after authentication with the test account.",
            "Manually verify logout invalidates the session; logout links were not invoked.",
            "Review lockout/rate limiting without repeated failed logins (no brute force performed).",
        ],
        "potential_findings": [],
    }
    header("Authentication / Session Analysis")
    section("Observed Behavior")
    info(f"HTTP status: {response.status_code}; password forms: {len(password_forms)}")
    info(f"Cookie names observed: {', '.join(initial_cookie_names) if initial_cookie_names else 'none'}; values withheld")
    if logout_refs:
        info(f"Logout reference(s) identified: {len(logout_refs)}; not invoked")
    if login_result:
        info(f"One test-account POST completed with HTTP {login_result['status_code']}; credential values were not retained")
        warn("Session rotation and authentication semantics require manual verification")
    else:
        warn("No login attempt was made. Use the explicit one-shot test-account option only on a controlled account.")
    return result
