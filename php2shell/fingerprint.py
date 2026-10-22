"""Passive PHP technology and version identification.

Everything here works on responses the scanner has already received. Nothing
in this module sends a request.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from php2shell.advisories import PATCH_MARKER_DIRECTIVE
from php2shell.confidence import Evidence, EvidenceKind
from php2shell.transport import HttpResponse

MAX_OBSERVED = 300


def _clip(s: str, n: int = MAX_OBSERVED) -> str:
    s = s.replace("\r", " ").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

PHP_TOKEN_RE = re.compile(r"\bPHP/(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?([0-9A-Za-z.~+:_\-]*)")
PHPINFO_VERSION_RE = re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{1,3})([0-9A-Za-z.~+:_\-]*)$")
PRERELEASE_RE = re.compile(r"^-?(dev|alpha\d*|beta\d*|RC\d*)$", re.I)

# Server banners for distributions whose PHP packages keep the upstream version
# number while backporting security fixes, and do not add a suffix to it.
BACKPORTING_PLATFORM_RE = re.compile(
    r"\((Red Hat Enterprise Linux|Red Hat|CentOS|CentOS Stream|AlmaLinux|Rocky Linux|"
    r"Oracle Linux|Oracle|Amazon Linux|Amazon|CloudLinux|SUSE|Linux/SUSE)[^)]*\)",
    re.I,
)


@dataclass(slots=True)
class PhpVersion:
    raw: str
    major: int
    minor: int
    patch: int | None
    suffix: str = ""
    vendor: str | None = None
    """Packaging vendor inferred from the suffix: debian, ubuntu, sury, rhel or unknown."""
    prerelease: bool = False
    backport_possible: bool = False
    """True when the packager may ship fixes without changing the upstream version."""

    @property
    def base(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch if self.patch is not None else 0)

    @property
    def branch(self) -> tuple[int, int]:
        return (self.major, self.minor)

    def __str__(self) -> str:
        return self.raw


def classify_suffix(suffix: str) -> tuple[str | None, bool, bool]:
    """Return (vendor, prerelease, backport_possible) for a version suffix."""
    if not suffix:
        return None, False, False
    s = suffix.lower()
    if PRERELEASE_RE.match(suffix):
        return None, True, False
    if "sury" in s:
        # deb.sury.org packages follow upstream point releases; the base version is meaningful.
        return "sury", False, False
    if "ubuntu" in s:
        return "ubuntu", False, True
    if "deb" in s:
        return "debian", False, True
    if re.search(r"\.el\d|\bel\d", s):
        return "rhel", False, True
    return "unknown", False, True


def parse_php_version(text: str) -> PhpVersion | None:
    """Parse a 'PHP/x.y.z[suffix]' token as found in X-Powered-By or Server headers."""
    m = PHP_TOKEN_RE.search(text or "")
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else None
    suffix = m.group(4) or ""
    vendor, pre, backport = classify_suffix(suffix)
    raw = f"{major}.{minor}" + (f".{patch}" if patch is not None else "") + suffix
    return PhpVersion(raw=raw, major=major, minor=minor, patch=patch, suffix=suffix,
                      vendor=vendor, prerelease=pre, backport_possible=backport)


def parse_bare_version(text: str) -> PhpVersion | None:
    """Parse a bare 'x.y.z[suffix]' version, e.g. from a phpinfo() heading."""
    m = PHPINFO_VERSION_RE.match((text or "").strip())
    if not m:
        return None
    suffix = m.group(4) or ""
    vendor, pre, backport = classify_suffix(suffix)
    return PhpVersion(raw=text.strip(), major=int(m.group(1)), minor=int(m.group(2)),
                      patch=int(m.group(3)), suffix=suffix, vendor=vendor,
                      prerelease=pre, backport_possible=backport)


# ---------------------------------------------------------------------------
# phpinfo() parsing
# ---------------------------------------------------------------------------

_PHPINFO_H1_RE = re.compile(r'<h1 class="p">\s*PHP Version\s+([^<\s]+)\s*</h1>', re.I)
_PHPINFO_ROW_RE = re.compile(
    r'<tr><td class="e">\s*(.*?)\s*</td>((?:<td class="v">.*?</td>)+)</tr>', re.I | re.S
)
_TD_V_RE = re.compile(r'<td class="v">(.*?)</td>', re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def _cell_text(s: str) -> str:
    return html.unescape(_TAG_RE.sub("", s)).strip()


@dataclass(slots=True)
class PhpInfo:
    url: str
    version: PhpVersion | None
    server_api: str | None
    system: str | None
    directives: dict[str, tuple[str, ...]] = field(default_factory=dict)
    info_rows: dict[str, str] = field(default_factory=dict)

    @property
    def core_table_parsed(self) -> bool:
        """True when the Core INI directive table is present, so absence of a directive is meaningful."""
        required = ("memory_limit", "max_execution_time", "post_max_size", "display_errors")
        return all(k in self.directives for k in required)

    @property
    def has_patch_marker(self) -> bool:
        return PATCH_MARKER_DIRECTIVE in self.directives

    def directive(self, name: str) -> str | None:
        vals = self.directives.get(name)
        return vals[0] if vals else None


def parse_phpinfo(body: str, url: str) -> PhpInfo | None:
    """Parse phpinfo() HTML output. Returns None if the body is not a phpinfo page."""
    if not body or "phpinfo()" not in body and "PHP Version" not in body:
        return None
    h1 = _PHPINFO_H1_RE.search(body)
    rows = _PHPINFO_ROW_RE.findall(body)
    if not h1 and not rows:
        return None
    directives: dict[str, tuple[str, ...]] = {}
    info_rows: dict[str, str] = {}
    for name_html, values_html in rows:
        name = _cell_text(name_html)
        values = tuple(_cell_text(v) for v in _TD_V_RE.findall(values_html))
        if len(values) >= 2:
            directives.setdefault(name, values)
        elif values:
            info_rows.setdefault(name, values[0])
    version = parse_bare_version(_cell_text(h1.group(1))) if h1 else None
    if version is None and "PHP Version" in info_rows:
        version = parse_bare_version(info_rows["PHP Version"])
    if version is None and not directives:
        return None
    return PhpInfo(
        url=url,
        version=version,
        server_api=info_rows.get("Server API"),
        system=info_rows.get("System"),
        directives=directives,
        info_rows=info_rows,
    )


# ---------------------------------------------------------------------------
# Passive signal extraction
# ---------------------------------------------------------------------------

PHP_SESSION_COOKIES = {
    "phpsessid": ("Default PHP session cookie name (session.name)", 0.6),
}
FRAMEWORK_COOKIES: dict[str, tuple[str, float]] = {
    "laravel_session": ("Laravel session cookie", 0.6),
    "ci_session": ("CodeIgniter session cookie", 0.55),
    "moodlesession": ("Moodle session cookie", 0.6),
    "wordpress_test_cookie": ("WordPress test cookie", 0.6),
    "wp-settings": ("WordPress settings cookie", 0.6),
    "symfony": ("Symfony session cookie", 0.5),
    "cakephp": ("CakePHP session cookie", 0.55),
    "zm_session": ("Zoneminder session cookie", 0.5),
    "prestashop": ("PrestaShop cookie", 0.55),
    "frontend": ("Magento frontend session cookie (generic name; weak)", 0.2),
}
DRUPAL_SESSION_RE = re.compile(r"^S?SESS[0-9a-f]{32}$", re.I)

PHP_ERROR_RE = re.compile(
    r"(<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>:\s.{0,200}?\son line\s<b>\d+</b>"
    r"|PHP (?:Fatal error|Parse error|Warning|Notice|Deprecated):\s.{0,200}?\son line \d+"
    r"|Stack trace:\s*#0 [^\n<]{0,200}\.php)",
    re.S,
)

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,120})["\']', re.I)
PHP_GENERATORS = {
    "wordpress": ("WordPress", 0.7),
    "drupal": ("Drupal", 0.7),
    "joomla": ("Joomla", 0.7),
    "typo3": ("TYPO3", 0.7),
    "mediawiki": ("MediaWiki", 0.7),
    "phpbb": ("phpBB", 0.7),
    "prestashop": ("PrestaShop", 0.7),
    "concrete": ("Concrete CMS", 0.6),
    "craft cms": ("Craft CMS", 0.6),
    "contao": ("Contao", 0.6),
}
BODY_MARKERS: tuple[tuple[re.Pattern, str, float], ...] = (
    (re.compile(r"/wp-(?:content|includes)/", re.I), "WordPress asset paths", 0.6),
    (re.compile(r"/sites/(?:default|all)/(?:files|modules|themes)/", re.I), "Drupal asset paths", 0.5),
    (re.compile(r"/media/jui/|/media/system/js/|/administrator/", re.I), "Joomla asset paths", 0.4),
    (re.compile(r"/skin/frontend/|Mage\.Cookies|/static/version\d+/frontend/", re.I), "Magento asset paths", 0.5),
)
NON_PHP_POWERED_BY: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bASP\.NET\b", re.I), "ASP.NET"),
    (re.compile(r"\bExpress\b"), "Node.js Express"),
    (re.compile(r"\bNext\.js\b", re.I), "Next.js"),
    (re.compile(r"\bServlet\b|\bJSP/", re.I), "Java Servlet/JSP"),
    (re.compile(r"\bPhusion Passenger\b", re.I), "Phusion Passenger (Ruby/Python/Node)"),
    (re.compile(r"\bNuxt\b", re.I), "Nuxt"),
)
NON_PHP_HEADERS: dict[str, str] = {
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-runtime": "Ruby on Rails (x-runtime)",
}
CDN_HEADERS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-served-by": "Fastly/Varnish",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-cdn": "CDN",
    "via": "proxy (Via header)",
    "x-cache": "cache (X-Cache header)",
    "x-varnish": "Varnish",
}
PHP_LINK_RE = re.compile(r'(?:href|action|src)=["\']([^"\'#?]{1,200}\.php)(?:[?#][^"\']*)?["\']', re.I)


def _cookie_name_value(raw: str) -> tuple[str, str]:
    first = raw.split(";", 1)[0]
    name, _, value = first.partition("=")
    return name.strip(), value.strip()


def extract_signals(resp: HttpResponse) -> list[Evidence]:
    """Extract PHP-presence, version, environment and non-PHP signals from a response."""
    ev: list[Evidence] = []
    url = resp.url

    xpb = resp.header("x-powered-by")
    if xpb:
        if "php" in xpb.lower():
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "header.x-powered-by",
                               "X-Powered-By header names PHP", url, _clip(xpb), weight=0.95))
            v = parse_php_version(xpb)
            if v:
                ev.append(Evidence(EvidenceKind.PHP_VERSION, "header.x-powered-by",
                                   f"PHP version {v.raw} disclosed in X-Powered-By", url, _clip(xpb)))
        else:
            for rx, name in NON_PHP_POWERED_BY:
                if rx.search(xpb):
                    ev.append(Evidence(EvidenceKind.NON_PHP, "header.x-powered-by",
                                       f"X-Powered-By identifies a non-PHP runtime ({name})", url,
                                       _clip(xpb), weight=0.8))
                    break

    server = resp.header("server")
    if server:
        v = parse_php_version(server)
        if v:
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "header.server",
                               "Server banner includes a PHP module token", url, _clip(server), weight=0.9))
            ev.append(Evidence(EvidenceKind.PHP_VERSION, "header.server",
                               f"PHP version {v.raw} disclosed in Server banner", url, _clip(server)))
        m = BACKPORTING_PLATFORM_RE.search(server)
        if m:
            ev.append(Evidence(EvidenceKind.ENVIRONMENT, "header.server.platform",
                               f"Server banner indicates {m.group(1)}, whose PHP packages may carry "
                               "backported fixes without a version change", url, _clip(server)))

    for hname, runtime in NON_PHP_HEADERS.items():
        val = resp.header(hname)
        if val:
            ev.append(Evidence(EvidenceKind.NON_PHP, f"header.{hname}",
                               f"{hname} header identifies {runtime}", url, _clip(val), weight=0.8))

    for hname in ("x-generator", "x-drupal-cache", "x-drupal-dynamic-cache", "x-pingback"):
        val = resp.header(hname)
        if not val:
            continue
        if hname == "x-generator":
            low = val.lower()
            for key, (name, w) in PHP_GENERATORS.items():
                if key in low:
                    ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "header.x-generator",
                                       f"X-Generator names {name}, a PHP application", url, _clip(val), weight=w))
                    break
        elif hname.startswith("x-drupal"):
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "header.x-drupal",
                               "Drupal cache header present", url, _clip(val), weight=0.7))
        elif hname == "x-pingback" and "xmlrpc.php" in val:
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "header.x-pingback",
                               "X-Pingback points at xmlrpc.php (WordPress)", url, _clip(val), weight=0.7))

    link = resp.header("link")
    if link and "api.w.org" in link:
        ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "header.link.wp-json",
                           "Link header advertises the WordPress REST API", url, _clip(link), weight=0.7))

    for raw in resp.set_cookies:
        name, value = _cookie_name_value(raw)
        low = name.lower()
        if low in PHP_SESSION_COOKIES:
            desc, w = PHP_SESSION_COOKIES[low]
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "cookie.phpsessid", desc, url,
                               _clip(f"{name}=<{len(value)} chars>"), weight=w))
        elif DRUPAL_SESSION_RE.match(name):
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "cookie.drupal",
                               "Drupal session cookie name pattern", url, _clip(name), weight=0.6))
        else:
            for key, (desc, w) in FRAMEWORK_COOKIES.items():
                if low == key or (key in ("wp-settings", "wordpress_test_cookie") and low.startswith(key)):
                    ev.append(Evidence(EvidenceKind.PHP_PRESENCE, f"cookie.{key}", desc, url,
                                       _clip(name), weight=w))
                    break

    for hname, cdn in CDN_HEADERS.items():
        val = resp.header(hname)
        if val:
            ev.append(Evidence(EvidenceKind.ENVIRONMENT, "header.cdn",
                               f"Response passed through {cdn}: headers may be rewritten, stripped or cached",
                               url, _clip(f"{hname}: {val}")))

    ev.extend(_body_signals(resp))
    return ev


def _body_signals(resp: HttpResponse) -> list[Evidence]:
    ev: list[Evidence] = []
    body = resp.body
    url = resp.url
    if not body:
        return ev
    ctype = (resp.header("content-type") or "").lower()
    if ctype and not any(t in ctype for t in ("html", "xml", "text")):
        return ev

    m = PHP_ERROR_RE.search(body)
    if m:
        ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "body.php-error",
                           "Response already contains a PHP error or stack trace", url,
                           _clip(_TAG_RE.sub("", m.group(0))), weight=0.85))

    gm = GENERATOR_RE.search(body)
    if gm:
        gen = html.unescape(gm.group(1))
        low = gen.lower()
        for key, (name, w) in PHP_GENERATORS.items():
            if key in low:
                ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "body.meta-generator",
                                   f"Meta generator names {name}, a PHP application", url, _clip(gen), weight=w))
                break

    for rx, desc, w in BODY_MARKERS:
        mm = rx.search(body)
        if mm:
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "body.framework-assets", desc, url,
                               _clip(mm.group(0)), weight=w))

    host = urlsplit(url).hostname
    for lm in PHP_LINK_RE.finditer(body):
        target = urljoin(url, html.unescape(lm.group(1)))
        if urlsplit(target).hostname == host:
            ev.append(Evidence(EvidenceKind.PHP_PRESENCE, "body.php-links",
                               "Same-host links to .php resources", url, _clip(lm.group(1)), weight=0.4))
            break

    return ev


def phpinfo_evidence(info: PhpInfo) -> list[Evidence]:
    """Evidence derived from a parsed phpinfo() page."""
    ev = [Evidence(EvidenceKind.PHP_PRESENCE, "phpinfo", "phpinfo() output is exposed", info.url,
                   "PHP Version " + (info.version.raw if info.version else "?"), weight=1.0)]
    if info.version:
        ev.append(Evidence(EvidenceKind.PHP_VERSION, "phpinfo",
                           f"PHP version {info.version.raw} reported by phpinfo()", info.url, info.version.raw))
    if info.server_api:
        ev.append(Evidence(EvidenceKind.ENVIRONMENT, "phpinfo.server-api",
                           f"Server API: {info.server_api}", info.url, _clip(info.server_api)))
    if info.system:
        ev.append(Evidence(EvidenceKind.ENVIRONMENT, "phpinfo.system", "System", info.url, _clip(info.system)))
    if info.core_table_parsed:
        if info.has_patch_marker:
            ev.append(Evidence(EvidenceKind.PATCH_MARKER, "phpinfo.patch-marker",
                               f"INI directive {PATCH_MARKER_DIRECTIVE} is registered: the build contains "
                               "the 'Avoid state corruption via bailout' fix",
                               info.url, _clip(f"{PATCH_MARKER_DIRECTIVE} => {info.directives[PATCH_MARKER_DIRECTIVE]}"),
                               validated=True))
        else:
            ev.append(Evidence(EvidenceKind.PATCH_MARKER, "phpinfo.patch-marker",
                               f"INI directive {PATCH_MARKER_DIRECTIVE} is absent from a complete Core "
                               "directive table: the build does not contain the fix",
                               info.url, f"{PATCH_MARKER_DIRECTIVE} not listed; "
                               f"{len(info.directives)} directives parsed", validated=True))
    for name in ("session.upload_progress.enabled", "fatal_error_backtraces", "memory_limit",
                 "post_max_size", "max_input_nesting_level", "display_errors", "opcache.enable"):
        val = info.directive(name)
        if val is not None:
            ev.append(Evidence(EvidenceKind.CONFIGURATION, f"phpinfo.ini.{name}",
                               f"{name} = {val}", info.url, _clip(val)))
    return ev
