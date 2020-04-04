import os
import websockets
import logging
import logging.config

_log_config_file_ = os.path.join(os.path.dirname(__file__), 'logging.conf')
logging.config.fileConfig(_log_config_file_)

from . import main

def start(*args, **kwargs):
    main.start(*args, **kwargs)

