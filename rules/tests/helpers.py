from rules.models import Rule, Ruleset, RuleVersion
from rules.services.editing import EditResult
from rules.services.parser import parse


def make_ruleset(
    text: str, name: str = "test", origin: Ruleset.Origin = Ruleset.Origin.MANUAL
) -> Ruleset:
    """A ruleset holding the rules of `text`, each at version 1, not yet compile-checked."""
    ruleset = Ruleset.objects.create(name=name, origin=origin, path=name)
    for position, parsed in enumerate(parse(text).rules):
        rule = Rule(ruleset=ruleset, position=position)
        rule.apply_parsed(parsed)
        rule.save()
        rule.set_tags(parsed.tags)
        rule.record_version(RuleVersion.Origin.CREATE)
    return ruleset


def saved_rule(result: EditResult) -> Rule:
    """The rule an editing service saved; fails the test if nothing was saved."""
    assert result.rule is not None, result.error
    return result.rule
