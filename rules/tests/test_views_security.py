"""
Air-gap and CSP evidence: no template, static file or rendered page refers to
another origin, and no page has inline scripts, inline styles or event
handler attributes. Every page carries the Content-Security-Policy header.
"""

import re
from html.parser import HTMLParser
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase
from django.urls import reverse

from rules.tests.test_views_common import ViewTestCase

BASE = Path(settings.BASE_DIR)
TEMPLATE_DIRS = [BASE / "rules" / "templates", BASE / "accounts" / "templates"]
STATIC_DIR = BASE / "rules" / "static"

# Attributes whose value the browser may fetch or navigate to.
URL_ATTRIBUTES = {"src", "href", "action", "formaction", "srcset", "poster", "data", "xlink:href"}
# The only absolute URL allowed in static files: the SVG namespace name, an
# identifier that is never fetched.
SVG_NAMESPACE = "http://www.w3.org/2000/svg"
REMOTE = re.compile(r"(?i)(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}|https?://")


def is_same_origin(url: str) -> bool:
    url = url.strip()
    if url.startswith("//"):
        return False
    if url.startswith(("/", "#", "?")) or url == "":
        return True
    if url.startswith("data:image/"):
        return True
    # A relative path without a scheme.
    return not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url)


class PageAudit(HTMLParser):
    """Collects CSP and same-origin violations from one HTML page."""

    def __init__(self):
        super().__init__()
        self.problems = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        for name, value in attrs:
            if name.startswith("on"):
                self.problems.append(f"<{tag} {name}=…> event handler attribute")
            if name == "style":
                self.problems.append(f"<{tag} style=…> inline style")
            if name in URL_ATTRIBUTES and value is not None:
                urls = (
                    [part.split()[0] for part in value.split(",")] if name == "srcset" else [value]
                )
                for url in urls:
                    if not is_same_origin(url):
                        self.problems.append(f"<{tag} {name}={url!r}> not same-origin")
        if tag == "script":
            if "src" not in attributes:
                self.problems.append("inline <script>")
            self._in_script = True
        if tag == "style":
            self.problems.append("<style> element")
        if tag == "link" and attributes.get("rel") in ("preconnect", "dns-prefetch"):
            self.problems.append("<link rel=preconnect/dns-prefetch>")
        if tag == "base":
            self.problems.append("<base> element")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.problems.append("inline script content")


def audit(html: str) -> list[str]:
    parser = PageAudit()
    parser.feed(html)
    return parser.problems


def strip_css_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


class StaticSourceTests(SimpleTestCase):
    def template_files(self):
        for directory in TEMPLATE_DIRS:
            yield from sorted(directory.rglob("*.html"))

    def test_templates_have_no_inline_code_or_remote_references(self):
        files = list(self.template_files())
        self.assertGreater(len(files), 15)
        patterns = {
            "style attribute": re.compile(r"\sstyle\s*="),
            "event handler attribute": re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
            "inline script": re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE),
            "<style> element": re.compile(r"<style[\s>]", re.IGNORECASE),
            "remote URL": REMOTE,
            "javascript: URL": re.compile(r"javascript:", re.IGNORECASE),
        }
        for path in files:
            text = path.read_text()
            for problem, pattern in patterns.items():
                with self.subTest(template=str(path.relative_to(BASE)), problem=problem):
                    self.assertIsNone(pattern.search(text))

    def test_static_files_reference_nothing_off_site(self):
        files = sorted(p for p in STATIC_DIR.rglob("*") if p.is_file())
        self.assertTrue(any(p.suffix == ".css" for p in files))
        self.assertTrue(any(p.suffix == ".js" for p in files))
        for path in files:
            text = path.read_text()
            with self.subTest(file=str(path.relative_to(BASE))):
                if path.suffix == ".css":
                    # Comments are dropped: the compiled CSS keeps Tailwind's
                    # MIT licence banner, which names its website.
                    text = strip_css_comments(text)
                    self.assertNotIn("@import", text)
                    self.assertNotIn("@font-face", text)
                    for url in re.findall(r"url\(\s*['\"]?([^'\")]*)", text):
                        self.assertTrue(is_same_origin(url) or url.startswith("data:"), url)
                elif path.suffix == ".svg":
                    text = text.replace(f'xmlns="{SVG_NAMESPACE}"', "")
                    self.assertNotIn("<script", text)
                    self.assertNotIn("href", text)
                elif path.suffix == ".js":
                    for forbidden in (
                        "fetch(",
                        "XMLHttpRequest",
                        "WebSocket",
                        "EventSource",
                        "sendBeacon",
                        "import(",
                        "eval(",
                        "new Function",
                    ):
                        self.assertNotIn(forbidden, text)
                self.assertIsNone(REMOTE.search(text), REMOTE.search(text))

    def test_only_expected_static_file_types(self):
        allowed = {".css", ".js", ".svg"}
        for path in STATIC_DIR.rglob("*"):
            if path.is_file():
                self.assertIn(path.suffix, allowed, path)


class RenderedPageTests(ViewTestCase):
    def pages(self):
        rule, ruleset, run = self.hello.pk, self.ruleset.pk, self.import_run.pk
        yield reverse("login"), None
        names = [
            ("dashboard", []),
            ("rule_list", []),
            ("rule_detail", [rule]),
            ("rule_detail", [self.broken.pk]),
            ("rule_create", []),
            ("rule_edit", [rule]),
            ("rule_delete", [rule]),
            ("rule_version", [rule, 1]),
            ("ruleset_list", []),
            ("ruleset_detail", [ruleset]),
            ("ruleset_delete", [ruleset]),
            ("import", []),
            ("import_run", [run]),
            ("scan", []),
        ]
        for name, args in names:
            yield reverse(f"rules:{name}", args=args), self.editor
        yield reverse("password_change"), self.editor
        yield reverse("password_change_done"), self.editor
        yield reverse("rules:rule_detail", args=[99999]), self.editor  # 404 page
        yield reverse("rules:dashboard"), self.nobody  # 403 page

    def test_every_page_is_csp_clean_and_same_origin(self):
        for url, user in self.pages():
            if user:
                self.client.force_login(user)
            else:
                self.client.logout()
            response = self.client.get(url)
            with self.subTest(url=url, user=getattr(user, "username", None)):
                self.assertIn(response.status_code, (200, 403, 404))
                csp = response.headers.get("Content-Security-Policy", "")
                self.assertIn("default-src 'self'", csp)
                self.assertNotIn("unsafe-inline", csp)
                self.assertEqual(audit(response.content.decode()), [])

    def test_rendered_results_are_clean(self):
        """Pages after a POST: editor results, scan results, export redirect."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.client.force_login(self.editor)
        responses = [
            self.client.post(
                reverse("rules:rule_edit", args=[self.hello.pk]),
                {"text": "rule x { condition: nope }", "version": 1, "action": "validate"},
            ),
            self.client.post(
                reverse("rules:scan"),
                {"sample": SimpleUploadedFile("s.bin", b"hello world")},
            ),
        ]
        for response in responses:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(audit(response.content.decode()), [])

    def test_audit_detects_violations(self):
        bad = (
            '<script>alert(1)</script><div style="x"></div><a onclick="x" href="https://e.x/">'
            '<img src="//cdn.example.com/a.png"><link rel="stylesheet" href="http://e.x/s.css">'
        )
        self.assertEqual(len(audit(bad)), 7)


class ErrorPageTests(SimpleTestCase):
    def test_500_and_csrf_pages_render_without_a_request(self):
        from django.template.loader import render_to_string

        for name in ("500.html", "400.html", "403_csrf.html"):
            with self.subTest(template=name):
                html = render_to_string(name)
                self.assertIn("rules/css/yaradude.css", html)
                self.assertEqual(audit(html), [])
