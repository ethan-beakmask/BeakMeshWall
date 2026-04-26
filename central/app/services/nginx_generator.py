"""Generate canonical /etc/nginx/conf.d/beakmeshwall/access.conf content.

The output is byte-deterministic for a given rule set so that drift
detection can compare hashes directly. See docs/NGINX-MANAGEMENT.md
sections 4.1 and 6.

Caller passes a list of dict rules already validated by nginx_validator.
"""
from app.schemas import nginx_fingerprint

ACCESS_CONF_HEADER = (
    "# MANAGED BY BeakMeshWall - DO NOT EDIT MANUALLY / "
    "由 BeakMeshWall 管理，請勿手動編輯\n"
    "# Source: BeakMeshWall central, see docs/NGINX-MANAGEMENT.md\n"
    "\n"
)


def _sort_key(rule: dict) -> tuple:
    """Ordering: deny before allow; 'all' last; otherwise lexicographic by src.

    Tuple (group, src_sort_token):
      group 0 = deny, 1 = allow non-all, 2 = allow all
      src_sort_token = src string (or '' for 'all' to keep stable)
    """
    action = rule.get("action")
    src = rule.get("src", "")
    if action == "deny":
        return (0, src)
    if src == "all":
        return (2, "")
    return (1, src)


def generate_access_conf(rules: list[dict]) -> str:
    """Render the rule list into the canonical access.conf body.

    rules: list of validated nginx schema rules.
    """
    body = ACCESS_CONF_HEADER
    for rule in sorted(rules, key=_sort_key):
        fp = nginx_fingerprint(rule)
        comment = rule.get("comment", "").strip()
        if comment:
            body += f"# BMW-ID={fp}: {comment}\n"
        else:
            body += f"# BMW-ID={fp}:\n"
        body += f"{rule['action']} {rule['src']};\n\n"
    return body
