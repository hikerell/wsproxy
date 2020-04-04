"""
wsproxy: A Secure High-Performace Proxy Based on Websocket

Usage:
    wsproxy.py -h
    wsproxy.py server start <config> [-d] [-v]
    wsproxy.py client start <config> [-d] [-v]
    wsproxy.py server (stop|status)
    wsproxy.py client (stop|status)

Options:
    -h --help       show help message
    -d --daemon     daemon mode
    -v --verbose    verbose mode
"""

import os
import sys
import json
import docopt

args = docopt.docopt(__doc__, version='wsproxy 1.0')
print(args)

cfg = None

def wsproxy_exit(reason):
    print('==================================')
    print('|         wsproxy failed         |')
    print('==================================')
    print(reason)
    sys.exit(0)

if args['<config>']:
    config = os.path.realpath(args['<config>'])
    if not os.path.exists(config):
        wsproxy_exit(f'config not found: {config}')
    if not os.path.isfile(config):
        wsproxy_exit(f'config not file: {config}')
    with open(config) as fr:
        try:
            cfg = json.loads(fr.read())
        except Exception as e:
            wsproxy_exit(f'config format invalid: {config}\r\njson parse error:\r\n\t{e}')

from common import daemon

if args['start']:
    print(f'wsproxy starting ... daemon={args["--daemon"]}')
    if args["--daemon"]:
        daemon.start()
    if args['server']:
        from server import main
        main.start(cfg)
    else:
        from client import main
        main.start(cfg)
elif args['stop']:
    daemon.stop()
elif args['status']:
    daemon.status()
