import secrets

import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

from app.extensions import db
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.threat_whitelist import ThreatWhitelist


@click.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@with_appcontext
def create_admin_cmd(username, password):
    """Create an admin user."""
    if User.query.filter_by(username=username).first():
        click.echo(f"User '{username}' already exists.")
        return
    user = User(username=username, role="admin")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"Admin user '{username}' created.")


@click.command("create-api-key")
@click.option("--name", prompt=True, help="Descriptive name for this API key")
@click.option(
    "--scope",
    type=click.Choice(["threat", "full"]),
    default="threat",
    help="Key scope: 'threat' for block/unblock only, 'full' for all operations",
)
@with_appcontext
def create_api_key_cmd(name, scope):
    """Generate a new API key and print it (shown only once)."""
    raw_key = secrets.token_hex(32)  # 64 hex chars
    prefix = raw_key[:8]

    api_key = ApiKey(
        name=name,
        key_hash=generate_password_hash(raw_key),
        prefix=prefix,
        scope=scope,
    )
    db.session.add(api_key)
    db.session.commit()

    click.echo(f"API Key created (scope: {scope}):")
    click.echo(f"  Name:   {name}")
    click.echo(f"  Prefix: {prefix}")
    click.echo(f"  Key:    {raw_key}")
    click.echo("Save this key now -- it cannot be retrieved again.")


@click.command("list-api-keys")
@with_appcontext
def list_api_keys_cmd():
    """List all API keys (prefix and name only)."""
    keys = ApiKey.query.order_by(ApiKey.id).all()
    if not keys:
        click.echo("No API keys found.")
        return
    click.echo(f"{'ID':<5} {'Prefix':<10} {'Name':<25} {'Scope':<10} {'Active':<8}")
    click.echo("-" * 60)
    for k in keys:
        click.echo(f"{k.id:<5} {k.prefix:<10} {k.name:<25} {k.scope:<10} {k.is_active!s:<8}")


@click.command("whitelist-add")
@click.option("--ip", prompt=True, help="IP address or CIDR to whitelist")
@click.option("--description", default="", help="Description of this entry")
@with_appcontext
def whitelist_add_cmd(ip, description):
    """Add an IP/CIDR to the threat whitelist."""
    import ipaddress as _ipa

    # Validate
    try:
        net = _ipa.ip_network(ip, strict=False)
        ip = str(net)
    except ValueError:
        click.echo(f"Invalid IP or CIDR: {ip}")
        return

    existing = ThreatWhitelist.query.filter_by(ip_cidr=ip).first()
    if existing:
        click.echo(f"'{ip}' already in whitelist (id={existing.id}).")
        return

    entry = ThreatWhitelist(ip_cidr=ip, description=description, created_by="cli")
    db.session.add(entry)
    db.session.commit()
    click.echo(f"Whitelist entry added: {ip} (id={entry.id})")


@click.command("whitelist-list")
@with_appcontext
def whitelist_list_cmd():
    """List all threat whitelist entries."""
    entries = ThreatWhitelist.query.order_by(ThreatWhitelist.id).all()
    if not entries:
        click.echo("Whitelist is empty.")
        return
    click.echo(f"{'ID':<5} {'IP/CIDR':<20} {'Description':<30} {'Created By':<15}")
    click.echo("-" * 72)
    for e in entries:
        click.echo(f"{e.id:<5} {e.ip_cidr:<20} {e.description:<30} {e.created_by:<15}")


@click.command("whitelist-remove")
@click.option("--id", "entry_id", type=int, prompt=True, help="Whitelist entry ID to remove")
@with_appcontext
def whitelist_remove_cmd(entry_id):
    """Remove a whitelist entry by ID."""
    entry = db.session.get(ThreatWhitelist, entry_id)
    if not entry:
        click.echo(f"Whitelist entry id={entry_id} not found.")
        return
    ip_cidr = entry.ip_cidr
    db.session.delete(entry)
    db.session.commit()
    click.echo(f"Removed whitelist entry: {ip_cidr} (id={entry_id})")


def register_cli(app):
    app.cli.add_command(create_admin_cmd)
    app.cli.add_command(create_api_key_cmd)
    app.cli.add_command(list_api_keys_cmd)
    app.cli.add_command(whitelist_add_cmd)
    app.cli.add_command(whitelist_list_cmd)
    app.cli.add_command(whitelist_remove_cmd)
