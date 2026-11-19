"""The API pages of the UI: every documentation page and the key pages render."""

from django.test import override_settings
from django.urls import reverse

from api import keys
from api.models import ApiKey
from api.pages import slug
from api.registry import ENDPOINTS, GROUPS
from api.tests.helpers import ApiTestCase
from rules.tests.test_views_security import PageAudit


def docs_urls() -> list[str]:
    """Overview and one page per group, from the same group list as the URLs."""
    return [reverse("api:docs")] + [reverse("api:docs_group", args=[slug(g)]) for g in GROUPS]


KEY_PAGE_URLS = [reverse("api:keys")]


class PagesRenderTests(ApiTestCase):
    def test_every_documentation_and_key_page_renders_for_every_role(self):
        for user in (self.viewer, self.editor, self.nobody, self.superuser):
            self.client.force_login(user)
            for url in [*docs_urls(), *KEY_PAGE_URLS]:
                with self.subTest(user=user.username, url=url):
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 200)
                    audit = PageAudit()
                    audit.feed(response.content.decode())
                    self.assertEqual(audit.problems, [])

    def test_downloads_render(self):
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("api:docs_openapi"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["openapi"], "3.1.0")
        response = self.client.get(reverse("api:docs_client"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("DEFAULT_URL = 'http://testserver'", response.content.decode())

    def test_unknown_group_is_404(self):
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("api:docs_group", args=["nope"]))
        self.assertEqual(response.status_code, 404)

    def test_pages_need_sign_in(self):
        for url in [*docs_urls(), *KEY_PAGE_URLS, reverse("api:docs_openapi")]:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertIn(reverse("login"), response["Location"])

    def test_every_endpoint_is_documented_on_its_group_page(self):
        self.client.force_login(self.viewer)
        pages = {g: self.client.get(reverse("api:docs_group", args=[slug(g)])) for g in GROUPS}
        for e in ENDPOINTS:
            with self.subTest(operation=e.operation):
                content = pages[e.group].content.decode()
                self.assertIn(f'id="{e.anchor}"', content)
                self.assertIn(f'id="curl-{e.anchor}"', content)
                self.assertIn(f'id="py-{e.anchor}"', content)

    @override_settings(ALLOWED_HOSTS=["yaradude.example.test"])
    def test_examples_use_the_host_being_browsed_and_no_key(self):
        _, secret = keys.create_key(self.viewer, "mine")
        self.client.force_login(self.viewer)
        content = self.client.get(
            reverse("api:docs_group", args=["rules"]), HTTP_HOST="yaradude.example.test"
        ).content.decode()
        self.assertIn("http://yaradude.example.test/api/v1/rules/", content)
        self.assertIn("$YARADUDE_API_KEY", content)
        self.assertNotIn(secret, content)
        self.assertNotIn(ApiKey.objects.get().public_id, content)


class KeyPageTests(ApiTestCase):
    def test_create_shows_the_key_once_and_stores_only_a_hash(self):
        self.client.force_login(self.viewer)
        response = self.client.post(reverse("api:keys"), {"name": "nightly", "expires": "30"})
        self.assertEqual(response.status_code, 201)
        self.assertIn("no-store", response["Cache-Control"])
        secret = response.context["secret"]
        self.assertRegex(secret, keys.KEY_RE)
        self.assertContains(response, secret, status_code=201)
        key = ApiKey.objects.get(user=self.viewer)
        self.assertEqual(key.name, "nightly")
        self.assertIsNotNone(key.expires_at)
        self.assertEqual(key.secret_sha256, keys.digest(secret))
        self.assertNotIn(secret, str(key.__dict__))
        # Shown once: the next view of the page lists the prefix only.
        again = self.client.get(reverse("api:keys"))
        self.assertNotContains(again, secret)
        self.assertContains(again, key.prefix)

    def test_create_validation(self):
        self.client.force_login(self.viewer)
        response = self.client.post(reverse("api:keys"), {"name": "bad\nname"})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(reverse("api:keys"), {"name": ""})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ApiKey.objects.exists())

    def test_key_limit(self):
        self.client.force_login(self.viewer)
        with self.settings(YARADUDE_API_MAX_KEYS_PER_USER=1):
            self.assertEqual(self.client.post(reverse("api:keys"), {"name": "a"}).status_code, 201)
            response = self.client.post(reverse("api:keys"), {"name": "b"})
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "at most 1", status_code=400)

    def test_revoke_own_key_only(self):
        mine, _ = keys.create_key(self.viewer, "mine")
        theirs, _ = keys.create_key(self.editor, "theirs")
        self.client.force_login(self.viewer)
        response = self.client.post(reverse("api:key_revoke", args=[theirs.pk]))
        self.assertEqual(response.status_code, 404)
        response = self.client.get(reverse("api:key_revoke", args=[mine.pk]))
        self.assertEqual(response.status_code, 405)
        response = self.client.post(reverse("api:key_revoke", args=[mine.pk]))
        self.assertRedirects(response, reverse("api:keys"))
        mine.refresh_from_db()
        theirs.refresh_from_db()
        self.assertTrue(mine.is_revoked)
        self.assertFalse(theirs.is_revoked)

    def test_list_shows_only_own_keys(self):
        keys.create_key(self.viewer, "mine")
        keys.create_key(self.editor, "theirs")
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("api:keys"))
        self.assertContains(response, "mine")
        self.assertNotContains(response, "theirs")

    def test_revoke_needs_csrf(self):
        mine, _ = keys.create_key(self.viewer, "mine")
        client = self.client_class(enforce_csrf_checks=True)
        client.force_login(self.viewer)
        response = client.post(reverse("api:key_revoke", args=[mine.pk]))
        self.assertEqual(response.status_code, 403)
        mine.refresh_from_db()
        self.assertFalse(mine.is_revoked)
