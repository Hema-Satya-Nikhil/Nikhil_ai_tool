"""Rate-limited HTTP client that validates scope before every request/redirect."""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urljoin, urlsplit

import requests
from requests.exceptions import RequestException

from nikhil_ai_modules.evidence import SENSITIVE_KEY, redact_text, sanitize_url
from nikhil_ai_modules.scope import ScopeError, normalize_host


class ResponseTooLargeError(ValueError):
    """Raised when a response body exceeds the configured hard size limit."""


class _ScopedSession(requests.Session):
    """Leave redirects untouched so the scoped client can verify each peer first."""

    def resolve_redirects(self, *_args, **_kwargs):
        # requests normally consumes a redirect response while precomputing its
        # next request, which can release the socket before peer verification.
        # Redirect following is implemented explicitly in ScopedHTTPClient.
        return iter(())


class RateLimiter:
    def __init__(self, interval: float = 1.0):
        self.interval = max(0.25, float(interval))
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self, cancel_event=None) -> None:
        from nikhil_ai_modules.events import ScanCancelled
        waited = 0.0
        with self._lock:
            while True:
                remaining = self._next - time.monotonic()
                if remaining <= 0:
                    self._next = time.monotonic() + self.interval
                    return waited
                portion = min(remaining, 0.2)
                if cancel_event is not None and cancel_event.wait(portion):
                    raise ScanCancelled("Scan cancelled while waiting for the request limiter")
                if cancel_event is None:
                    time.sleep(portion)
                waited += portion


class ScopedHTTPClient:
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    SUPPORTED_METHODS = SAFE_METHODS | {"POST"}

    def __init__(self, scope, config: Dict[str, Any], logger=None, events=None):
        self.scope = scope
        self.config = config
        self.logger = logger
        self.events = events
        self.rate_limiter = RateLimiter(config.get("request_interval", 1.0))
        self._local = threading.local()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = _ScopedSession()
            session.trust_env = False  # do not let ambient proxy settings change scan routing
            session.headers.update({"User-Agent": str(self.config.get("user_agent", "NIKHIL-AI-Safe/2.0"))})
            self._local.session = session
        return session

    @staticmethod
    def _read_bounded(response: requests.Response, maximum: int) -> None:
        try:
            advertised_size = int(response.headers.get("Content-Length", ""))
        except (TypeError, ValueError):
            advertised_size = 0
        if advertised_size > maximum:
            response.close()
            raise ResponseTooLargeError(f"Response exceeds the configured {maximum}-byte limit")

        chunks = []
        total_read = 0
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            if len(chunk) > maximum - total_read:
                response.close()
                raise ResponseTooLargeError(f"Response exceeds the configured {maximum}-byte limit")
            chunks.append(chunk)
            total_read += len(chunk)
        response._content = b"".join(chunks)
        response._content_consumed = True
        response._nikhil_response_size = max(advertised_size, total_read)
        response._nikhil_truncated = False
        response._nikhil_redirect_chain = []
        response.close()

    @staticmethod
    def _verify_peer(response: requests.Response, approved_addresses) -> None:
        raw = getattr(response, "raw", None)
        connection = getattr(raw, "_connection", None)
        sock = getattr(connection, "sock", None)
        if sock is None:
            fp = getattr(raw, "_fp", None)
            inner = getattr(fp, "fp", None)
            raw_socket = getattr(inner, "raw", None)
            sock = getattr(raw_socket, "_sock", None)
        if sock is None:
            response.close()
            raise ScopeError("Could not verify the connected peer address; request blocked")
        try:
            peer = normalize_host(sock.getpeername()[0])
        except (OSError, IndexError, TypeError, ValueError) as exc:
            response.close()
            raise ScopeError("Could not verify the connected peer address; request blocked") from exc
        approved = {normalize_host(address) for address in approved_addresses}
        if peer not in approved:
            response.close()
            raise ScopeError(f"Connected peer {peer} differs from DNS-validated scope addresses; request blocked")

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = normalize_host(parsed.hostname or "")
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        timeout: Optional[float] = None,
        allow_post: bool = False,
        purpose: str = "target",
        max_redirects: Optional[int] = None,
    ) -> requests.Response:
        verb = str(method or "GET").upper()
        if verb not in self.SUPPORTED_METHODS:
            raise ValueError(f"HTTP method {verb} is not supported by the safe client")
        if verb == "POST" and (self.config.get("safe_mode", True) and not allow_post):
            raise ScopeError("Safe Mode blocks POST unless a scanner explicitly requests a human-approved test-account action")
        if verb not in self.SAFE_METHODS and verb != "POST":
            raise ScopeError(f"Safe Mode blocks HTTP method {verb}")

        session = self._session()
        merged_headers = dict(headers or {})
        redirects_allowed = max_redirects if max_redirects is not None else self.config.get("max_redirects", 5)
        retries = max(0, min(int(self.config.get("max_retries", 1)), 2)) if verb in self.SAFE_METHODS else 0
        current_url = url
        redirect_chain = []
        first_request = True
        credential_origin = None

        for redirect_count in range(int(redirects_allowed) + 1):
            # This authorization gate runs before every network attempt and
            # redirect. The actual connected peer is also compared to the
            # checked DNS answers to resist DNS-rebinding changes.
            response = None
            attempt = 0
            checked_url = None
            while True:
                try:
                    checked_url, approved_addresses = self.scope.authorize_url(current_url, purpose=purpose)
                except ScopeError as exc:
                    if self.events:
                        self.events.fail_scope(current_url, str(exc))
                    raise
                request_origin = self._origin(checked_url)
                if credential_origin is None:
                    credential_origin = request_origin
                elif request_origin != credential_origin:
                    # The redirect is in scope, but it is a different origin.
                    # Do not forward researcher-supplied credentials/cookies or
                    # routing headers to another host, scheme, or port.
                    merged_headers = {
                        name: value for name, value in merged_headers.items()
                        if not SENSITIVE_KEY.search(str(name))
                        and str(name).lower() not in {"host", "origin", "referer"}
                    }
                if self.events:
                    self.events.before_request(verb, checked_url)
                runtime = self.events.runtime() if self.events else None
                control = runtime.get("control") if runtime else None
                limiter_wait = self.rate_limiter.acquire(getattr(control, "cancel_event", None))
                if limiter_wait >= 0.2 and self.events:
                    self.events.publish("rate_limit", severity="info", target=checked_url, message="Request delayed by the shared rate limiter", data={"wait_seconds": round(limiter_wait, 3)})
                if control is not None:
                    control.wait_for_resume()
                request_started = time.monotonic()
                try:
                    session.cookies.clear()
                    response = session.request(
                        verb,
                        checked_url,
                        headers=merged_headers,
                        params=params if first_request else None,
                        # A body on a GET is unusual but accepted by requests; never
                        # replay it when following a redirect, especially cross-origin.
                        data=data if first_request else None,
                        json=json if first_request else None,
                        timeout=timeout or self.config.get("timeout", 6.0),
                        allow_redirects=False,
                        stream=True,
                    )
                    session.cookies.clear()
                    self._verify_peer(response, approved_addresses)
                    if verb == "HEAD":
                        try:
                            head_size = int(response.headers.get("Content-Length", "0"))
                        except (TypeError, ValueError):
                            head_size = 0
                        response._content = b""
                        response._content_consumed = True
                        response._nikhil_response_size = max(0, head_size)
                        response._nikhil_truncated = False
                        response._nikhil_redirect_chain = []
                        response.close()
                    else:
                        self._read_bounded(response, int(self.config.get("max_response_bytes", 1048576)))
                    if self.events:
                        self.events.after_request(verb, checked_url, response.status_code, time.monotonic() - request_started)
                except RequestException as exc:
                    session.cookies.clear()
                    if self.events:
                        self.events.after_request(verb, checked_url or current_url, None, time.monotonic() - request_started)
                    if attempt < retries:
                        attempt += 1
                        if self.events:
                            self.events.publish("task_retry", severity="warning", target=checked_url, message="Retrying a safe HTTP request", data={"attempt": attempt, "method": verb})
                        if self.logger:
                            self.logger.warning("HTTP retry for %s: %s", sanitize_url(checked_url), redact_text(exc, 300))
                        continue
                    if self.logger:
                        self.logger.warning("HTTP request failed for %s: %s", sanitize_url(checked_url), redact_text(exc, 300))
                    raise
                except Exception:
                    session.cookies.clear()
                    if self.events:
                        self.events.after_request(verb, checked_url or current_url, None, time.monotonic() - request_started)
                    raise
                if response.status_code >= 500 and attempt < retries:
                    response.close()
                    attempt += 1
                    if self.events:
                        self.events.publish("task_retry", severity="warning", target=checked_url, message="Retrying after an HTTP server error", data={"attempt": attempt, "status_code": response.status_code})
                    continue
                break

            first_request = False
            response._nikhil_redirect_chain = list(redirect_chain)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("Location")
            if not location or redirect_count >= int(redirects_allowed):
                return response
            next_url = urljoin(checked_url, location)
            # Never replay a POST across a redirect in this conservative client.
            if verb == "POST":
                return response
            redirect_chain.append({"url": sanitize_url(checked_url), "status": response.status_code})
            response.close()
            current_url = next_url
        raise RequestException("Redirect limit exceeded")

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, *, allow_post: bool = False, **kwargs) -> requests.Response:
        return self.request("POST", url, allow_post=allow_post, **kwargs)


def response_size(response: requests.Response) -> int:
    return int(getattr(response, "_nikhil_response_size", len(response.content or b"")))


def response_truncated(response: requests.Response) -> bool:
    return bool(getattr(response, "_nikhil_truncated", False))
