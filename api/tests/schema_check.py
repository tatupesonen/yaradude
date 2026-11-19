"""
A small JSON Schema checker for the subset api.schemas uses (type, nullable
types, properties, required, additionalProperties, items, enum, anyOf,
$ref), so tests can check real responses against the documentation.
"""

from typing import Any

from api.schemas import COMPONENTS

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def errors(value: Any, schema: dict[str, Any], where: str = "$") -> list[str]:
    if "$ref" in schema:
        return errors(value, COMPONENTS[schema["$ref"].rsplit("/", 1)[1]], where)
    if "anyOf" in schema:
        options = [errors(value, option, where) for option in schema["anyOf"]]
        return [] if any(not found for found in options) else min(options, key=len)
    problems: list[str] = []
    kinds = schema.get("type")
    if kinds is not None:
        kinds = kinds if isinstance(kinds, list) else [kinds]
        ok = any(
            isinstance(value, TYPES[kind])
            and not (kind in ("integer", "number") and isinstance(value, bool))
            for kind in kinds
        )
        if not ok:
            return [f"{where}: {value!r} is not {kinds}"]
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{where}: {value!r} not in {schema['enum']}")
    if isinstance(value, dict) and "properties" in schema:
        properties = schema["properties"]
        for name in schema.get("required", []):
            if name not in value:
                problems.append(f"{where}: missing {name}")
        for name, item in value.items():
            if name in properties:
                problems += errors(item, properties[name], f"{where}.{name}")
            elif schema.get("additionalProperties") is False:
                problems.append(f"{where}: undocumented property {name}")
    if isinstance(value, dict) and isinstance(schema.get("additionalProperties"), dict):
        for name, item in value.items():
            problems += errors(item, schema["additionalProperties"], f"{where}.{name}")
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            problems += errors(item, schema["items"], f"{where}[{index}]")
    return problems
