import pytest

from php2shell.detection import VersionStatus, version_status
from php2shell.fingerprint import classify_suffix, parse_bare_version, parse_php_version


@pytest.mark.parametrize("header,raw,base,vendor,backport", [
    ("PHP/8.4.26", "8.4.26", (8, 4, 26), None, False),
    ("PHP/8.2.12", "8.2.12", (8, 2, 12), None, False),
    ("PHP/8.1.2-1ubuntu2.22", "8.1.2-1ubuntu2.22", (8, 1, 2), "ubuntu", True),
    ("PHP/8.3.6-0ubuntu0.24.04.5", "8.3.6-0ubuntu0.24.04.5", (8, 3, 6), "ubuntu", True),
    ("PHP/8.2.29-1~deb12u1", "8.2.29-1~deb12u1", (8, 2, 29), "debian", True),
    ("PHP/7.4.33-1+deb11u8", "7.4.33-1+deb11u8", (7, 4, 33), "debian", True),
    ("PHP/8.4.13-1+ubuntu24.04.1+deb.sury.org+1", "8.4.13-1+ubuntu24.04.1+deb.sury.org+1", (8, 4, 13), "sury", False),
    ("PHP/8.0.30.el9", "8.0.30.el9", (8, 0, 30), "rhel", True),
    ("PHP/5.6.40", "5.6.40", (5, 6, 40), None, False),
    ("Apache/2.4.62 (Debian) PHP/8.2.7 OpenSSL/3.0", "8.2.7", (8, 2, 7), None, False),
    ("PHP/8.5.0RC2", "8.5.0RC2", (8, 5, 0), None, False),
])
def test_parse_header_versions(header, raw, base, vendor, backport):
    v = parse_php_version(header)
    assert v is not None
    assert v.raw == raw
    assert v.base == base
    assert v.vendor == vendor
    assert v.backport_possible is backport


def test_branch_only_version():
    v = parse_php_version("PHP/8.4")
    assert v.patch is None and v.branch == (8, 4)


@pytest.mark.parametrize("value", ["", "ASP.NET", "PHPX/8.1", "Express", "PHP", "PHP/"])
def test_no_version(value):
    assert parse_php_version(value) is None


def test_prerelease_flag():
    assert classify_suffix("RC1") == (None, True, False)
    assert classify_suffix("-dev") == (None, True, False)


def test_bare_version():
    assert parse_bare_version("8.4.27").base == (8, 4, 27)
    assert parse_bare_version("8.2.28-1~deb12u1").vendor == "debian"
    assert parse_bare_version("not a version") is None


@pytest.mark.parametrize("ver,status", [
    ("8.2.34", VersionStatus.AFFECTED), ("8.2.35", VersionStatus.FIXED), ("8.2.36", VersionStatus.FIXED),
    ("8.3.35", VersionStatus.AFFECTED), ("8.3.36", VersionStatus.FIXED),
    ("8.4.26", VersionStatus.AFFECTED), ("8.4.27", VersionStatus.FIXED),
    ("8.5.11", VersionStatus.AFFECTED), ("8.5.12", VersionStatus.FIXED),
    ("8.5.0RC2", VersionStatus.AFFECTED),
    ("8.1.33", VersionStatus.AFFECTED), ("7.4.33", VersionStatus.AFFECTED), ("5.4.45", VersionStatus.AFFECTED),
    ("8.6.0", VersionStatus.UNKNOWN), ("9.0.0", VersionStatus.UNKNOWN),
])
def test_version_status_boundaries(ver, status):
    assert version_status(parse_php_version("PHP/" + ver))[0] == status


def test_branch_only_supported_is_unknown_but_eol_is_affected():
    assert version_status(parse_php_version("PHP/8.4"))[0] == VersionStatus.UNKNOWN
    assert version_status(parse_php_version("PHP/7.4"))[0] == VersionStatus.AFFECTED
