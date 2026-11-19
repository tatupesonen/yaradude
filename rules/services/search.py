"""
Substring search over rules with an SQLite FTS5 trigram index (PLAN.md
sections 5.7 and 12.5).

`rules_rule_fts` is an external-content FTS5 table over the name,
description, author and source columns of `rules_rule`, created by
migration 0004 and kept in sync by triggers on `rules_rule` for every insert,
update and delete, whatever issues them (ORM saves, bulk operations,
`QuerySet.update/delete`, cascades, raw SQL). All rules are indexed, removed
ones included; callers filter by status on the queryset as before.

Semantics, the same as the `icontains` filter it replaces: the whole input
(trimmed) is one literal substring, matched case-insensitively in any of
the four columns; several words are a phrase, not AND-ed. Input of fewer
than three characters cannot use trigrams and falls back to `icontains`
(so does input containing a NUL character).
One difference: the index folds case for non-ASCII letters too ("JÜRGEN"
finds "Jürgen"), where SQLite's LIKE folds ASCII only.
"""

import sqlite3

from django.db import connection
from django.db.models import FloatField, Q, QuerySet
from django.db.models.expressions import RawSQL

from rules.models import Rule

FTS_TABLE = "rules_rule_fts"
MIN_TERM = 3  # the trigram tokenizer cannot match shorter input
COLUMNS = ("name", "description", "author", "source")


def fts_support() -> str:
    """
    '' if the SQLite library Django uses supports FTS5 with the trigram
    tokenizer (SQLite 3.34 or newer, built with FTS5), else the reason.
    """
    try:
        probe = sqlite3.connect(":memory:")
        try:
            probe.execute("CREATE VIRTUAL TABLE t USING fts5(x, tokenize='trigram')")
        finally:
            probe.close()
    except sqlite3.Error as error:
        return (
            f"SQLite {sqlite3.sqlite_version} lacks FTS5 with the trigram tokenizer "
            f"({error}); yaradude needs SQLite 3.34 or newer built with FTS5."
        )
    return ""


def match_expression(text: str) -> str:
    """
    `text` as an FTS5 query that matches it literally: one string token
    with embedded double quotes doubled, so operators (AND, OR, NOT, NEAR),
    column filters (`name:`), prefixes (`*`), `^`, `-` and parentheses lose
    their meaning.
    """
    return '"' + text.replace('"', '""') + '"'


def search_rules(queryset: QuerySet[Rule], text: str, *, rank: bool = False) -> QuerySet[Rule]:
    """
    The rules of `queryset` whose name, description, author or source
    contains `text` (trimmed; case-insensitive). Returns a queryset that can
    still be filtered, ordered and paginated. With `rank`, it is annotated
    with `search_rank` (FTS5 bm25: lower is better; None for short input) and
    ordered by it, then by primary key; otherwise the queryset's ordering is
    kept. Empty `text` returns `queryset` unchanged.
    """
    text = text.strip()
    if not text:
        return queryset
    if len(text) < MIN_TERM or "\x00" in text:
        # Too short for trigrams, or holding a NUL, which FTS5's query
        # parser cannot take: the plain substring match.
        q = Q()
        for column in COLUMNS:
            q |= Q(**{f"{column}__icontains": text})
        found = queryset.filter(q)
        if rank:
            found = found.annotate(
                search_rank=RawSQL("NULL", [], output_field=FloatField())
            ).order_by("pk")
        return found
    match = match_expression(text)
    if not rank:
        return queryset.filter(
            pk__in=RawSQL(f"SELECT rowid FROM {FTS_TABLE} WHERE {FTS_TABLE} MATCH %s", [match])
        )
    # Ranking needs the FTS row next to each rule: join the index table
    # (a correlated subquery per row would re-run the match for every row).
    return queryset.extra(
        select={"search_rank": f"{FTS_TABLE}.rank"},
        tables=[FTS_TABLE],
        where=[f'{FTS_TABLE}.rowid = "rules_rule"."id"', f"{FTS_TABLE} MATCH %s"],
        params=[match],
    ).order_by("search_rank", "pk")


# The triggers that keep the index in sync. SQLite drops a table's triggers
# when Django rebuilds the table in a migration (as it does for many
# AlterField/AddField operations), so `ensure_index` recreates them after
# every `migrate` (post_migrate) instead of trusting migration 0004 alone.
TRIGGERS = {
    "rules_rule_fts_insert": f"""
        CREATE TRIGGER IF NOT EXISTS rules_rule_fts_insert AFTER INSERT ON rules_rule BEGIN
            INSERT INTO {FTS_TABLE}(rowid, name, description, author, source)
            VALUES (new.id, new.name, new.description, new.author, new.source);
        END
    """,
    "rules_rule_fts_delete": f"""
        CREATE TRIGGER IF NOT EXISTS rules_rule_fts_delete AFTER DELETE ON rules_rule BEGIN
            INSERT INTO {FTS_TABLE}({FTS_TABLE}, rowid, name, description, author, source)
            VALUES ('delete', old.id, old.name, old.description, old.author, old.source);
        END
    """,
    "rules_rule_fts_update": f"""
        CREATE TRIGGER IF NOT EXISTS rules_rule_fts_update AFTER UPDATE ON rules_rule
        WHEN old.id IS NOT new.id OR old.name IS NOT new.name
            OR old.description IS NOT new.description OR old.author IS NOT new.author
            OR old.source IS NOT new.source
        BEGIN
            INSERT INTO {FTS_TABLE}({FTS_TABLE}, rowid, name, description, author, source)
            VALUES ('delete', old.id, old.name, old.description, old.author, old.source);
            INSERT INTO {FTS_TABLE}(rowid, name, description, author, source)
            VALUES (new.id, new.name, new.description, new.author, new.source);
        END
    """,
}


def ensure_index(using: str = "default") -> bool:
    """
    Make sure the sync triggers exist; if any was missing (dropped by a table
    rebuild), recreate them and rebuild the index, which may have missed
    writes meanwhile. Returns True if it had to repair. Does nothing before
    migration 0004 has created the index table.
    """
    from django.db import connections

    with connections[using].cursor() as cursor:
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger') "
            "AND name IN (%s, %s, %s, %s)",
            [FTS_TABLE, *TRIGGERS],
        )
        present = {row[0] for row in cursor.fetchall()}
        if FTS_TABLE not in present or present >= {FTS_TABLE, *TRIGGERS}:
            return False
        for sql in TRIGGERS.values():
            cursor.execute(sql)
        cursor.execute(f"INSERT INTO {FTS_TABLE}({FTS_TABLE}) VALUES('rebuild')")
    return True


def rebuild_index() -> int:
    """Rebuild the search index from the rule table; returns the number of rules indexed."""
    with connection.cursor() as cursor:
        cursor.execute(f"INSERT INTO {FTS_TABLE}({FTS_TABLE}) VALUES('rebuild')")
    return Rule.objects.count()


def index_is_consistent() -> bool:
    """FTS5's own integrity check of the index against the rule table."""
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {FTS_TABLE}({FTS_TABLE}, rank) VALUES('integrity-check', 1)"
            )
    except Exception:
        return False
    return True
