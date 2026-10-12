#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from version import VERSION, VERSION_FULL
from recon import load_wordlist
from cve.catalog import _build_cpe
from cve.nvd import _is_false_positive, _product_in_summary
from cve.version import (
    _cpe_matches_product,
    _cpe_version_verdict,
    _parse_version,
    _version_in_range,
)
from common import t
from config import cargar as load_config

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


def test_parse_version():
    check("parse 1.2.3", _parse_version("1.2.3") == (1, 2, 3))
    check("parse 0", _parse_version("0") == (0,))
    check("parse abc", _parse_version("abc") == (0,))
    check("parse 1.2.3.4", _parse_version("1.2.3.4") == (1, 2, 3, 4))


def test_version_in_range():
    check("versions X to Y true", _version_in_range("2.4.6", "versions 2.4.0 to 2.4.10") == True)
    check("versions X to Y inclusive", _version_in_range("2.4.29", "versions 2.2.0 to 2.4.29") == True)
    check("versions X to Y false", _version_in_range("2.5.0", "versions 2.4.0 to 2.4.29") == False)
    check("X through Y true", _version_in_range("2.4.6", "2.4.0 through 2.4.10") == True)
    check("X through Y false", _version_in_range("2.4.6", "8.0.0 through 9.2.0") == False)
    check("before X true", _version_in_range("2.4.6", "before 2.4.10") == True)
    check("before X false", _version_in_range("2.4.6", "before 2.4.5") == False)
    check("prior to X", _version_in_range("2.4.6", "prior to 2.4.10") == True)
    check("through X true", _version_in_range("2.4.6", "through 2.4.10") == True)
    check("through X inclusive", _version_in_range("2.4.6", "through 2.4.6") == True)
    check("X and earlier <= X", _version_in_range("2.4.6", "2.4.6 and earlier") == True)
    check("X and earlier < X", _version_in_range("2.4.5", "2.4.6 and earlier") == True)
    check("X and earlier > X", _version_in_range("2.4.7", "2.4.6 and earlier") == False)


def test_product_in_summary():
    check("multi-word match", _product_in_summary("apache http server", "apache http server 2.4.6") == True)
    check("multi-word no match", _product_in_summary("apache http server", "nginx 1.20") == False)
    check("short name match", _product_in_summary("acl", "the acl package") == True)
    check("short name no substring", _product_in_summary("acl", "aclcheck module") == False)
    check("normal name match", _product_in_summary("python", "python 3.12") == True)


def test_false_positive():
    check("ed in privileged", _is_false_positive("ed", "a privileged vault operator") == True)
    check("dashmachine", _is_false_positive("dash", "rmountjoy92 dashmachine") == True)
    check("dash alliance", _is_false_positive("dash", "DASH 7 Alliance protocol") == True)
    check("winnt mpm", _is_false_positive("apache", "winnt_accept function in winnt mpm") == True)
    check("php cve for apache", _is_false_positive("apache", "in php before 5.4") == True)
    check("apache cve not fp", _is_false_positive("apache", "apache http server before 2.4.30") == False)



def test_build_cpe():
    check("apache http_server CPE",
          _build_cpe("Apache HTTP Server", "2.4.49")
          == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    check("openssl CPE", _build_cpe("OpenSSL", "3.0.2")
          == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*")
    check("unknown product has no CPE", _build_cpe("Not A Real Product", "1.0") is None)
    check("non-numeric version rejected", _build_cpe("Apache HTTP Server", "unknown") is None)


def test_cpe_product_match():
    check("http_server matches Apache HTTP Server", _cpe_matches_product("http_server", "Apache HTTP Server"))
    check("tomcat matches Apache Tomcat", _cpe_matches_product("tomcat", "Apache Tomcat"))
    check("unrelated product rejected", not _cpe_matches_product("nginx", "Apache HTTP Server"))


def test_cpe_version_verdict():
    # Real NVD configuration data for CVE-2017-7659, which affects only
    # Apache HTTP Server 2.4.24 and 2.4.25.
    only_2424_2425 = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:2.4.24:*:*:*:*:*:*:*"},
                    {"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*"},
                ]
            }]
        }]
    }
    # Regression: the summary-only heuristic said "unknown" and the CVE was
    # reported for 2.4.49, which is not affected.
    check("2.4.24 is affected",
          _cpe_version_verdict(only_2424_2425, "2.4.24", "Apache HTTP Server") is True)
    check("2.4.25 is affected",
          _cpe_version_verdict(only_2424_2425, "2.4.25", "Apache HTTP Server") is True)
    check("2.4.49 NOT affected (was a false positive)",
          _cpe_version_verdict(only_2424_2425, "2.4.49", "Apache HTTP Server") is False)

    # Wildcard version means every version is affected.
    wildcard = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
                ]
            }]
        }]
    }
    check("wildcard affects all versions",
          _cpe_version_verdict(wildcard, "9.9.9", "Apache HTTP Server") is True)

    # Explicit range bounds.
    ranged = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "2.4.0",
                     "versionEndExcluding": "2.4.50"}
                ]
            }]
        }]
    }
    check("inside inclusive range",
          _cpe_version_verdict(ranged, "2.4.49", "Apache HTTP Server") is True)
    check("outside exclusive end",
          _cpe_version_verdict(ranged, "2.4.50", "Apache HTTP Server") is False)

    # Different product entirely: no opinion.
    check("other product -> unknown",
          _cpe_version_verdict(only_2424_2425, "2.4.49", "nginx") is None)



def test_load_wordlist():
    import tempfile
    import os as _os

    # A fresh clone has no wordlist file: must fall back, not raise.
    check("no config -> built-in list", len(load_wordlist({})) > 100)
    check("missing file -> built-in list",
          len(load_wordlist({"recon": {"subdomains": {"wordlist": "nope.txt"}}})) > 100)

    with tempfile.TemporaryDirectory() as d:
        path = _os.path.join(d, "subs.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("www\nmail\n# comment\n\ndev\nbad.entry\n")
        got = load_wordlist({"recon": {"subdomains": {"wordlist": path}}})
        check("custom wordlist is read", got == ["dev", "mail", "www"], str(got))


print(f"Testing {VERSION_FULL}")
print()

test_parse_version()
test_version_in_range()
test_product_in_summary()
test_false_positive()
test_build_cpe()
test_cpe_product_match()
test_cpe_version_verdict()
test_load_wordlist()

print()
print(f"Tests: {passed + failed}  |  Passed: {passed}  |  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
