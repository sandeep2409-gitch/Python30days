"""API Clients for querying public breach databases."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import List, Optional

from breach_checker.models import BreachRecord, CheckResult, Status

DEFAULT_USER_AGENT = "BreachChecker-PythonChallenge/1.0"


class BaseBreachClient(ABC):
    """Abstract base class for breach checking clients."""

    name: str = "base"

    @abstractmethod
    def check(self, account: str) -> CheckResult:
        """Check an email or username for breach exposures."""
        pass


class XposedOrNotClient(BaseBreachClient):
    """Client for XposedOrNot free public API.
    
    Endpoint: https://api.xposedornot.com/v1/check-email/{email}
    No API key required for public email breach checks.
    """

    name: str = "xposedornot"
    BASE_URL: str = "https://api.xposedornot.com/v1/check-email/"

    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout

    def check(self, account: str) -> CheckResult:
        target = account.strip()
        start_time = time.time()

        # XposedOrNot requires an email format
        if "@" not in target:
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message="XposedOrNot only supports email addresses. For usernames, use HIBP with an API key.",
                response_time=time.time() - start_time,
            )

        encoded_email = urllib.parse.quote(target)
        url = f"{self.BASE_URL}{encoded_email}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = time.time() - start_time
                status_code = resp.getcode()
                raw_body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw_body) if raw_body else {}

                # Check for "Error": "Not found" or null email
                if data.get("Error") == "Not found" or (data.get("email") is None and not data.get("breaches")):
                    return CheckResult(
                        account=target,
                        provider=self.name,
                        status=Status.CLEAN,
                        breaches=[],
                        response_time=elapsed,
                    )

                # Parse breaches list (XposedOrNot often nests breaches: [["Adobe", "LinkedIn"]])
                raw_breaches = data.get("breaches", [])
                breach_names: List[str] = []
                for item in raw_breaches:
                    if isinstance(item, list):
                        breach_names.extend([str(x) for x in item])
                    elif isinstance(item, str):
                        breach_names.append(item)

                if breach_names:
                    records = [BreachRecord(name=b_name) for b_name in breach_names]
                    return CheckResult(
                        account=target,
                        provider=self.name,
                        status=Status.BREACHED,
                        breaches=records,
                        response_time=elapsed,
                    )

                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.CLEAN,
                    breaches=[],
                    response_time=elapsed,
                )

        except urllib.error.HTTPError as e:
            elapsed = time.time() - start_time
            if e.code == 404:
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.CLEAN,
                    breaches=[],
                    response_time=elapsed,
                )
            elif e.code == 429:
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.ERROR,
                    error_message="Rate limited by XposedOrNot (HTTP 429). Please wait before querying again.",
                    response_time=elapsed,
                )
            else:
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.ERROR,
                    error_message=f"HTTP {e.code}: {e.reason}",
                    response_time=elapsed,
                )
        except urllib.error.URLError as e:
            elapsed = time.time() - start_time
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message=f"Network error: {e.reason}",
                response_time=elapsed,
            )
        except json.JSONDecodeError:
            elapsed = time.time() - start_time
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message="Invalid JSON response received from XposedOrNot.",
                response_time=elapsed,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                response_time=elapsed,
            )


class HIBPClient(BaseBreachClient):
    """Client for Have I Been Pwned API v3.
    
    Endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{account}
    Requires a paid HIBP API Key.
    """

    name: str = "hibp"
    BASE_URL: str = "https://haveibeenpwned.com/api/v3/breachedaccount/"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 12.0):
        self.api_key = api_key or os.getenv("HIBP_API_KEY")
        self.timeout = timeout

    def check(self, account: str) -> CheckResult:
        target = account.strip()
        start_time = time.time()

        if not self.api_key:
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message="Missing HIBP API key. Provide via --api-key or HIBP_API_KEY environment variable.",
                response_time=time.time() - start_time,
            )

        encoded_account = urllib.parse.quote(target)
        url = f"{self.BASE_URL}{encoded_account}?truncateResponse=false"
        req = urllib.request.Request(
            url,
            headers={
                "hibp-api-key": self.api_key,
                "user-agent": DEFAULT_USER_AGENT,
                "Accept": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = time.time() - start_time
                raw_body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw_body) if raw_body else []

                records: List[BreachRecord] = []
                for item in data:
                    records.append(
                        BreachRecord(
                            name=item.get("Name", "Unknown"),
                            title=item.get("Title"),
                            domain=item.get("Domain"),
                            breach_date=item.get("BreachDate"),
                            pwn_count=item.get("PwnCount"),
                            data_classes=item.get("DataClasses", []),
                            description=item.get("Description"),
                        )
                    )

                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.BREACHED if records else Status.CLEAN,
                    breaches=records,
                    response_time=elapsed,
                )

        except urllib.error.HTTPError as e:
            elapsed = time.time() - start_time
            if e.code == 404:
                # 404 on HIBP means account was NOT found in any breaches (Clean)
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.CLEAN,
                    breaches=[],
                    response_time=elapsed,
                )
            elif e.code == 401:
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.ERROR,
                    error_message="HTTP 401 Unauthorized: Invalid or missing HIBP API key.",
                    response_time=elapsed,
                )
            elif e.code == 429:
                retry_after = e.headers.get("Retry-After", "unknown")
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.ERROR,
                    error_message=f"HTTP 429 Rate Limited: HIBP requested waiting {retry_after} seconds.",
                    response_time=elapsed,
                )
            else:
                return CheckResult(
                    account=target,
                    provider=self.name,
                    status=Status.ERROR,
                    error_message=f"HTTP {e.code}: {e.reason}",
                    response_time=elapsed,
                )
        except urllib.error.URLError as e:
            elapsed = time.time() - start_time
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message=f"Network error: {e.reason}",
                response_time=elapsed,
            )
        except json.JSONDecodeError:
            elapsed = time.time() - start_time
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message="Invalid JSON response received from HIBP.",
                response_time=elapsed,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return CheckResult(
                account=target,
                provider=self.name,
                status=Status.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                response_time=elapsed,
            )


def get_client(provider: str = "auto", api_key: Optional[str] = None) -> BaseBreachClient:
    """Instantiate appropriate breach client based on provider selection and API key."""
    chosen_key = api_key or os.getenv("HIBP_API_KEY")
    p = provider.lower()

    if p == "hibp":
        return HIBPClient(api_key=chosen_key)
    elif p == "xposedornot":
        return XposedOrNotClient()
    elif p == "auto":
        # If API key is available, prefer HIBP; otherwise use free XposedOrNot
        if chosen_key:
            return HIBPClient(api_key=chosen_key)
        return XposedOrNotClient()
    else:
        raise ValueError(f"Unknown provider '{provider}'. Choose 'auto', 'xposedornot', or 'hibp'.")

