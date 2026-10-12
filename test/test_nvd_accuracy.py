#!/usr/bin/env python3
"""Regression checks for CVE result completeness and false positives.

These compare NetSpy's output against NVD's own ``virtualMatchString`` answer
for the same product and version, which is the authoritative source.

Live tests hit the NVD API and need network access. They are skipped
automatically when it is unavailable.

    python3 test/test_nvd_accuracy.py
"""

import json
import sys
import os
import time
import urllib.error
from urllib.parse import quote
from urllib.request import urlopen

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from cve.catalog import _build_cpe  # noqa: E402
from cve.nvd import query_nvd  # noqa: E402

# (product, version, expected_count)
# Counts taken from NVD virtualMatchString on 2026-10-08. A mismatch means
# NetSpy is either dropping real CVEs or inventing them.
CASES = [
    ("Apache HTTP Server", "2.4.49", 88),
    ("Apache HTTP Server", "2.4.58", 67),
    ("Apache HTTP Server", "2.4.65", 48),
    ("nginx", "1.18.0", 6),
    ("nginx", "1.27.0", 1),
    ("OpenSSL", "3.3.0", 18),
    ("OpenSSL", "3.0.2", 67),
]

# CVE that Apache 2.4.49 is NOT affected by. It affects only 2.4.24/2.4.25 and
# was previously reported as a HIGH finding against 2.4.49.
MUST_NOT_APPEAR = ("Apache HTTP Server", "2.4.49", "CVE-2017-7659")

# CVEs that must be found on Apache 2.4.49 (both CVSS 9.8).
MUST_APPEAR = (
    ("Apache HTTP Server", "2.4.49", "CVE-2021-42013"),
    ("Apache HTTP Server", "2.4.49", "CVE-2021-41773"),
)

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [OK] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} - {detail}")


def nvd_reference_count(cpe):
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?virtualMatchString={quote(cpe)}"
    )
    with urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode()).get("totalResults", 0)


def main():
    print("Testing CVE accuracy against NVD (live)\n")

    try:
        first = query_nvd("Apache HTTP Server", "2.4.49")
        if first is None:
            raise RuntimeError("no response")
    except Exception as exc:
        print(f"  [SKIP] NVD unreachable: {exc}")
        return 0

    print("Counts match NVD exactly:")
    for product, version, expected in CASES:
        cpe = _build_cpe(product, version)
        if not cpe:
            check(f"{product} {version} has a CPE mapping", False, "no CPE built")
            continue
        got = len(query_nvd(product, version))
        check(
            f"{product} {version} -> {got} CVEs",
            got == expected,
            f"expected {expected}, got {got} (missing {expected - got})"
            if got < expected
            else f"expected {expected}, got {got} ({got - expected} extra = possible false positives)",
        )
        time.sleep(6)  # stay under NVD's unauthenticated rate limit

    print("\nKnown false positive is gone:")
    product, version, cve_id = MUST_NOT_APPEAR
    ids = {c["id"] for c in query_nvd(product, version)}
    check(f"{cve_id} not reported for {product} {version}", cve_id not in ids)
    time.sleep(6)

    print("\nCritical CVEs are found:")
    product, version = "Apache HTTP Server", "2.4.49"
    ids = {c["id"] for c in query_nvd(product, version)}
    for _, _, cve_id in MUST_APPEAR:
        check(f"{cve_id} reported for {product} {version}", cve_id in ids)

    print("\nAll CPE-query results are marked version-verified:")
    unverified = [
        c["id"]
        for c in query_nvd("OpenSSL", "3.3.0")
        if not c.get("version_verified")
    ]
    check("no unverified results from a CPE query", not unverified, str(unverified[:5]))

    print()
    print(f"Tests: {passed + failed}  |  Passed: {passed}  |  Failed: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())