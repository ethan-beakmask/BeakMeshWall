import click
from flask.cli import with_appcontext
from app.extensions import db
from app.models.user import User


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


def register_cli(app):
    app.cli.add_command(create_admin_cmd)
