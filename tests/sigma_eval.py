"""A small Sigma evaluator, so fixture events can be run against the canonical
rules in CI.

It implements the subset of the Sigma specification these rules use, and
refuses anything else rather than guessing:

* field conditions: plain values, and the modifiers contains, startswith,
  endswith, re and cidr
* lists of values (any may match), several fields in one block (all must match)
* conditions built from identifiers, and / or / not, and parentheses

Semantics follow the Sigma specification: plain string matches are
case-insensitive with * and ? wildcards; `re` is a case-sensitive regular
expression search; `cidr` tests IP membership; a missing field never matches.
"""
import ipaddress
import re

import yaml

SUPPORTED = {"contains", "startswith", "endswith", "re", "cidr"}


class Unsupported(Exception):
    pass


def _wildcard_to_regex(value: str) -> str:
    """Sigma plain-string value -> regex body (unanchored).

    `*` and `?` are wildcards; `\\*`, `\\?` and `\\\\` are escapes; any other
    backslash is a literal backslash (as in Windows paths). The value is parsed
    on its own, before modifiers add wildcards, exactly as pySigma does, so a
    value ending in a backslash stays a literal backslash under |contains."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _match_value(actual, expected, mods) -> bool:
    if actual is None:
        return False
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    body = _wildcard_to_regex(str(expected))
    if "contains" in mods:
        body = f".*{body}.*"
    elif "startswith" in mods:
        body = f"{body}.*"
    elif "endswith" in mods:
        body = f".*{body}"
    return re.fullmatch(body, str(actual), re.IGNORECASE | re.DOTALL) is not None


def _match_block(block, event) -> bool:
    if isinstance(block, list):  # list of maps: any may match
        return any(_match_block(b, event) for b in block)
    if not isinstance(block, dict):
        raise Unsupported(f"keyword detections are not supported: {block!r}")
    for key, expected in block.items():
        field, *mods = key.split("|")
        unknown = set(mods) - SUPPORTED
        if unknown:
            raise Unsupported(f"modifier(s) {unknown} in {key}")
        values = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(event.get(field), v, mods) for v in values):
            return False
    return True


def _tokens(condition: str):
    for tok in re.findall(r"\(|\)|[A-Za-z0-9_*]+", condition):
        yield tok


def _parse(tokens, blocks, event):
    """Recursive-descent: or > and > not > atom."""
    toks = list(tokens)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def expr_or():
        v = expr_and()
        while peek() == "or":
            take()
            r = expr_and()
            v = v or r
        return v

    def expr_and():
        v = expr_not()
        while peek() == "and":
            take()
            r = expr_not()
            v = v and r
        return v

    def expr_not():
        if peek() == "not":
            take()
            return not expr_not()
        return atom()

    def atom():
        t = take()
        if t == "(":
            v = expr_or()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return v
        if t in ("1", "all") or t.endswith("*"):
            raise Unsupported("'1 of' / 'all of' conditions are not supported")
        if t not in blocks:
            raise Unsupported(f"unknown identifier {t!r}")
        return _match_block(blocks[t], event)

    result = expr_or()
    if pos != len(toks):
        raise Unsupported(f"trailing tokens in condition: {toks[pos:]}")
    return result


def load_rule(path):
    with open(path) as f:
        return yaml.safe_load(f)


def matches(rule, event) -> bool:
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    if isinstance(condition, list):
        return any(_parse(_tokens(c), detection, event) for c in condition)
    return _parse(_tokens(condition), detection, event)
