"""
API endpoint modules. Importing this package registers every endpoint with
api.registry (done in ApiConfig.ready); the order below is the order of the
documentation within each group.
"""

from api.endpoints import account, deleted, imports, rules, rulesets, scan, scans

__all__ = ["account", "deleted", "imports", "rules", "rulesets", "scan", "scans"]
