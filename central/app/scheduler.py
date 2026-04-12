"""
Background scheduler for periodic maintenance tasks.

Currently runs:
    - expire_stale_rules: removes expired firewall rules and dispatches unblock tasks.
"""

import os
import logging

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

_scheduler = None


def init_scheduler(app):
    """Start the background scheduler within the Flask app context.

    Skipped when:
        - TESTING mode is enabled
        - Flask reloader spawns the extra process (only the reloader child runs jobs)
    """
    global _scheduler

    if app.config.get('TESTING', False):
        return

    # Werkzeug reloader forks twice; only start in the child process
    if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return

    interval = app.config.get('RULE_EXPIRY_CHECK_INTERVAL', 60)

    def expire_rules_job():
        with app.app_context():
            from .services.firewall_service import FirewallService
            expired = FirewallService.expire_stale_rules()
            if expired:
                logger.info('Expired %d stale rule(s).', len(expired))

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        expire_rules_job, 'interval', seconds=interval,
        id='expire_stale_rules', replace_existing=True,
    )
    _scheduler.start()

    logger.info('Background scheduler started (rule expiry check every %ds).', interval)
