import io
import tempfile
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.db import connection
from django.db.models import Q, QuerySet
from django.test import TestCase, override_settings

from rules.apps import check_full_text_search
from rules.models import Rule, Ruleset
from rules.services import editing
from rules.services.compiler import check_ruleset
from rules.services.importer import import_directory
from rules.services.search import (
    FTS_TABLE,
    index_is_consistent,
    match_expression,
    search_rules,
)
from rules.tests.helpers import make_ruleset

FIXTURE = r"""import "pe"

// Detects Mimikatz credential dumping.
rule mimikatz_strings : hacktool credential {
    meta:
        description = "Mimikatz strings, 100% sure_thing"
        author = "Florian Roth"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide
        $b = "kiwi_passwords" nocase
    condition:
        any of them
}

rule pe_dll_check {
    meta:
        description = "Generic DLL check AND NOT exe"
        author = "Jürgen Müller"
    condition:
        pe.is_dll() and filesize < 2MB
}

rule cve_2021_44228 : log4j {
    meta:
        description = "Log4Shell \"jndi:ldap\" lookups (name: attempt)"
        author = "someone else"
    strings:
        $j = "${jndi:ldap://" nocase
        $x = { 24 7B 6A 6E 64 69 }
    condition:
        $j or -1 < 0 and $x
}

rule backslash_rule {
    meta:
        description = "path C:\\Windows\\System32 and a*b^c"
    condition:
        filesize > 0
}
"""

QUERIES = [
    "mimikatz",
    "MIMIKATZ",
    "Mimikatz strings",  # several words: one phrase
    "strings mimikatz",  # not adjacent: no match, as with LIKE
    "credential dumping",
    "florian",
    "Roth",
    "100%",
    "% sure",
    "sure_thing",
    "_th",
    "pe.is_dll()",
    "is_dll() and",
    "AND NOT",
    "and not exe",
    "jndi:ldap",
    '"jndi',
    'Shell "jndi:ldap"',
    "name: attempt",
    "name:",
    "-1 < 0",
    "${jndi",
    "24 7B 6A",
    "C:\\Windows",
    "\\System32",
    "a*b",
    "a*b^c",
    "NEAR(",
    "(name",
    "rule ",
    "}\n\nrule",
    "condition:\n        filesize",
    "nothing like this",
]
SHORT = ["pe", "PE", "%", "_", "a*", '"', "\\", "x", "4j"]


def like(queryset: QuerySet[Rule], text: str) -> QuerySet[Rule]:
    """The search the rule list used before full-text search."""
    text = text.strip()
    return queryset.filter(
        Q(name__icontains=text)
        | Q(description__icontains=text)
        | Q(author__icontains=text)
        | Q(source__icontains=text)
    )


class SearchTestCase(TestCase):
    def setUp(self) -> None:
        self.ruleset = make_ruleset(FIXTURE)
        check_ruleset(self.ruleset)

    def ids(self, queryset: QuerySet[Rule]) -> list[int]:
        return sorted(queryset.values_list("pk", flat=True))

    def assertSameAsLike(self, text: str) -> None:
        self.assertEqual(
            self.ids(search_rules(Rule.objects.all(), text)),
            self.ids(like(Rule.objects.all(), text)),
            text,
        )


class SemanticsTests(SearchTestCase):
    def test_results_equal_the_like_search(self) -> None:
        for text in QUERIES:
            with self.subTest(text=text):
                self.assertSameAsLike(text)
        self.assertTrue(search_rules(Rule.objects.all(), "Mimikatz strings").exists())
        self.assertFalse(search_rules(Rule.objects.all(), "strings mimikatz").exists())

    def test_short_terms_fall_back_to_like(self) -> None:
        for text in SHORT:
            with self.subTest(text=text):
                self.assertSameAsLike(text)

    def test_surrounding_whitespace_is_trimmed_and_empty_is_everything(self) -> None:
        self.assertSameAsLike("  mimikatz  ")
        everything = Rule.objects.all()
        self.assertEqual(self.ids(search_rules(everything, "   ")), self.ids(everything))

    def test_non_ascii_case_is_folded(self) -> None:
        # LIKE only folds ASCII; the index folds other letters too.
        self.assertTrue(search_rules(Rule.objects.all(), "JÜRGEN").exists())
        self.assertFalse(like(Rule.objects.all(), "JÜRGEN").exists())

    def test_hostile_query_strings_are_literal(self) -> None:
        hostile = [
            '"',
            '""',
            '"""',
            "AND",
            "OR OR",
            "NOT x",
            "NEAR(a b)",
            "name:",
            "source:mimikatz",
            "{name author}: x",
            "-x",
            "- -",
            "*",
            "mimi*",
            "^mimikatz",
            "(((",
            ")))",
            "'; DROP TABLE rules_rule; --",
            "a\x00b",
            "\\",
            "\u202e\u2028",
            "x" * 2000,
        ]
        for text in hostile:
            with self.subTest(text=text):
                self.assertSameAsLike(text)
        self.assertTrue(Rule.objects.exists())

    def test_match_expression(self) -> None:
        self.assertEqual(match_expression('a "b" c'), '"a ""b"" c"')

    def test_queryset_stays_usable(self) -> None:
        found = search_rules(Rule.objects.active().order_by("-name"), "rule")
        self.assertEqual(found.count(), 4)
        self.assertEqual(
            list(found.values_list("name", flat=True)),
            ["pe_dll_check", "mimikatz_strings", "cve_2021_44228", "backslash_rule"],
        )
        self.assertEqual(found.filter(name__startswith="pe").count(), 1)
        self.assertEqual(len(found[1:3]), 2)
        Rule.objects.filter(name="pe_dll_check").update(removed_at="2026-01-01T00:00Z")
        self.assertEqual(search_rules(Rule.objects.active(), "Jürgen").count(), 0)
        self.assertEqual(search_rules(Rule.objects.removed(), "Jürgen").count(), 1)

    def test_rank_ordering(self) -> None:
        ranked = list(search_rules(Rule.objects.all(), "mimikatz", rank=True))
        self.assertEqual(ranked[0].name, "mimikatz_strings")
        self.assertTrue(all(rule.search_rank is not None for rule in ranked))
        short = list(search_rules(Rule.objects.all(), "pe", rank=True))
        self.assertTrue(short and all(rule.search_rank is None for rule in short))

    def test_uses_the_index(self) -> None:
        sql, params = search_rules(Rule.objects.all(), "mimikatz").query.sql_with_params()
        with connection.cursor() as cursor:
            cursor.execute("EXPLAIN QUERY PLAN " + sql, params)
            plan = " ".join(row[3] for row in cursor.fetchall())
        self.assertIn("VIRTUAL TABLE INDEX", plan)
        self.assertIn(FTS_TABLE, plan)


class SyncTests(SearchTestCase):
    """The index follows every write path (it is maintained by triggers)."""

    def assertFinds(self, text: str, names: list[str]) -> None:
        self.assertEqual(
            sorted(search_rules(Rule.objects.all(), text).values_list("name", flat=True)),
            sorted(names),
        )
        self.assertSameAsLike(text)
        self.assertTrue(index_is_consistent())

    def test_editing_services(self) -> None:
        rule = Rule.objects.get(name="backslash_rule")
        result = editing.update_rule(
            rule, 'rule backslash_rule { meta: author = "Zebedee" condition: true }'
        )
        self.assertTrue(result.ok, result.error)
        self.assertFinds("Zebedee", ["backslash_rule"])
        self.assertFinds("System32", [])
        editing.restore_version(rule.versions.get(number=1))
        self.assertFinds("System32", ["backslash_rule"])
        editing.update_rule(
            Rule.objects.get(name="backslash_rule"), "rule renamed_one { condition: true }"
        )
        self.assertFinds("renamed_one", ["renamed_one"])
        editing.create_rule(
            self.ruleset, 'rule brand_new { meta: description = "Quokka" condition: true }'
        )
        self.assertFinds("quokka", ["brand_new"])
        editing.delete_rule(Rule.objects.get(name="brand_new"))
        self.assertFinds("quokka", [])
        editing.delete_ruleset(self.ruleset)
        self.assertFinds("mimikatz", [])

    def test_imports(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(override_settings(YARADUDE_RULES_DIR=root))
        path = root / "set.yar"
        path.write_text('rule imported_one { meta: description = "Wombat" condition: true }\n')
        import_directory(root)
        self.assertFinds("wombat", ["imported_one"])
        path.write_text('rule imported_one { meta: description = "Numbat" condition: true }\n')
        import_directory(root)
        self.assertFinds("wombat", [])
        self.assertFinds("numbat", ["imported_one"])
        path.write_text("rule other { condition: true }\n")
        import_directory(root)  # imported_one is flagged removed, still indexed
        self.assertFinds("numbat", ["imported_one"])

    def test_bulk_and_raw_writes(self) -> None:
        Rule.objects.filter(name="pe_dll_check").update(description="Platypus")
        self.assertFinds("platypus", ["pe_dll_check"])
        rules = list(Rule.objects.filter(name__in=["cve_2021_44228", "mimikatz_strings"]))
        for rule in rules:
            rule.author = "Echidna"
        Rule.objects.bulk_update(rules, ["author"])
        self.assertFinds("echidna", ["cve_2021_44228", "mimikatz_strings"])
        Rule.objects.bulk_create(
            [Rule(ruleset=self.ruleset, name="bulk_made", source="rule bulk_made {}", sha256="x")]
        )
        self.assertFinds("bulk_made", ["bulk_made"])
        with connection.cursor() as cursor:
            cursor.execute("UPDATE rules_rule SET name = 'raw_renamed' WHERE name = 'bulk_made'")
        self.assertFinds("raw_renamed", ["raw_renamed"])
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM rules_rule WHERE name = 'raw_renamed'")
        self.assertFinds("raw_renamed", [])
        Rule.objects.filter(name="pe_dll_check").delete()  # QuerySet.delete
        self.assertFinds("platypus", [])
        Ruleset.objects.filter(pk=self.ruleset.pk).delete()  # ORM cascade
        self.assertFinds("echidna", [])
        self.assertEqual(Rule.objects.count(), 0)

    def test_admin_delete(self) -> None:
        from accounts.models import User

        self.client.force_login(User.objects.create_superuser("admin", email="", password="pw"))
        rule = Rule.objects.get(name="mimikatz_strings")
        self.client.post(f"/admin/rules/rule/{rule.pk}/delete/", {"post": "yes"})
        self.assertFinds("mimikatz", [])


class RebuildAndCheckTests(SearchTestCase):
    def test_rebuild_command_repairs_the_index(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(f"INSERT INTO {FTS_TABLE}({FTS_TABLE}) VALUES('delete-all')")
        self.assertFalse(search_rules(Rule.objects.all(), "mimikatz").exists())
        self.assertFalse(index_is_consistent())
        out = io.StringIO()
        call_command("rebuild_search_index", stdout=out)
        self.assertIn("Search index rebuilt: 4 rules.", out.getvalue())
        self.assertTrue(search_rules(Rule.objects.all(), "mimikatz").exists())
        self.assertTrue(index_is_consistent())

    def test_system_check(self) -> None:
        self.assertEqual(check_full_text_search(), [])
        with mock.patch("rules.services.search.fts_support", return_value="no fts5"):
            [error] = check_full_text_search()
        self.assertEqual((error.id, error.msg), ("rules.E001", "no fts5"))
