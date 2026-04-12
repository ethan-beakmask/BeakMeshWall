"""
BeakMeshWall Central Server entry point.

Load config from BMW_CONFIG env var or default config name.
Run on 0.0.0.0:5000 (host/port configurable via env vars).
"""

import os
from app import create_app

config_name = os.environ.get('BMW_CONFIG', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    host = os.environ.get('BMW_HOST', '0.0.0.0')
    port = int(os.environ.get('BMW_PORT', 5000))
    debug = config_name == 'development'
    app.run(host=host, port=port, debug=debug)
