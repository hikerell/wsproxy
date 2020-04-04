import os, sys 
import signal, atexit

def get_default_daemonize_pidfile():
    PATH_PID_FILE = '/tmp/wsproxy.pid'
    return PATH_PID_FILE

def start(pidfile=''):
    if not pidfile:
        pidfile = get_default_daemonize_pidfile()
    unix_daemonize_start(pidfile)

def stop(pidfile=''):
    if not pidfile:
        pidfile = get_default_daemonize_pidfile()
    unix_daemonize_stop(pidfile)

def status(pidfile=''):
    if not pidfile:
        pidfile = get_default_daemonize_pidfile()
    unix_daemonize_status(pidfile)

def unix_daemonize_start(pidfile, *, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    if not pidfile:
        pidfile = get_default_daemonize_pidfile()
    if os.path.exists(pidfile):
        with open(pidfile) as fr:
            pid = int(fr.read())
        print(f'already running in daemon: pid={pid}')
    # First fork (detaches from parent)
    try:
        if os.fork() > 0:
            sys.exit(0)   # Parent exit
    except OSError as e:
        raise RuntimeError('unix daemonize: fork #1 failed.')
    os.chdir('/')
    os.umask(0)
    os.setsid()
    # Second fork (relinquish session leadership)
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        raise RuntimeError('unix daemonize: fork #2 failed.')
    # Flush I/O buffers
    sys.stdout.flush()
    sys.stderr.flush()
    # Replace file descriptors for stdin, stdout, and stderr
    with open(stdin, 'rb', 0) as fr:
        os.dup2(fr.fileno(), sys.stdin.fileno())
    with open(stdout, 'ab', 0) as fw:
        os.dup2(fw.fileno(), sys.stdout.fileno())
    with open(stderr, 'ab', 0) as fe:
        os.dup2(fe.fileno(), sys.stderr.fileno())
    # Write the PID file
    with open(pidfile, 'w') as fpid:
        print(os.getpid(), file=fpid)
    # Arrange to have the PID file removed on exit/signal
    atexit.register(lambda: os.remove(pidfile))
    # Signal handler for termination (required)
    def sigterm_handler(signo, frame):
        raise SystemExit(1)
    signal.signal(signal.SIGTERM, sigterm_handler)

def unix_daemonize_stop(pidfile):
    if os.path.exists(pidfile):
        with open(pidfile) as fr:
            pid = int(fr.read())
        print(f'stopping the daemon: pid={pid}')
        os.kill(pid, signal.SIGTERM)
    else:
        print(f'not running in daemon mode.')
        raise SystemExit(1)

def unix_daemonize_status(pidfile):
    if os.path.exists(pidfile):
        with open(pidfile) as fr:
            pid = int(fr.read())
        print(f'running in daemon mode: pid={pid}')
    else:
        print(f'not running in daemon mode.')
        raise SystemExit(1)