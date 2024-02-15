from fixtures import *  # noqa: F401,F403
import subprocess
from pathlib import PosixPath, Path
import socket
from pyln.testing.utils import VALGRIND
import pytest
import os
import shutil
import time
import unittest


@pytest.fixture(autouse=True)
def canned_github_server(directory):
    global NETWORK
    NETWORK = os.environ.get('TEST_NETWORK')
    if NETWORK is None:
        NETWORK = 'regtest'
    FILE_PATH = Path(os.path.dirname(os.path.realpath(__file__)))
    if os.environ.get('LIGHTNING_CLI') is None:
        os.environ['LIGHTNING_CLI'] = str(FILE_PATH.parent / 'cli/lightning-cli')
        print('LIGHTNING_CALL: ', os.environ.get('LIGHTNING_CLI'))
    # Use socket to provision a random free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    free_port = str(sock.getsockname()[1])
    sock.close()
    global my_env
    my_env = os.environ.copy()
    # This tells reckless to redirect to the canned server rather than github.
    my_env['REDIR_GITHUB_API'] = f'http://127.0.0.1:{free_port}/api'
    my_env['REDIR_GITHUB'] = directory
    my_env['FLASK_RUN_PORT'] = free_port
    my_env['FLASK_APP'] = str(FILE_PATH / 'rkls_github_canned_server')
    server = subprocess.Popen(["python3", "-m", "flask", "run"],
                              env=my_env)

    # Generate test plugin repository to test reckless against.
    repo_dir = os.path.join(directory, "lightningd")
    os.mkdir(repo_dir, 0o777)
    plugins_path = str(FILE_PATH / 'data/recklessrepo/lightningd')
    # This lets us temporarily set .gitconfig user info in order to commit
    my_env['HOME'] = directory
    with open(os.path.join(directory, '.gitconfig'), 'w') as conf:
        conf.write(("[user]\n"
                    "\temail = reckless@example.com\n"
                    "\tname = reckless CI\n"
                    "\t[init]\n"
                    "\tdefaultBranch = master"))

    with open(os.path.join(directory, '.gitconfig'), 'r') as conf:
        print(conf.readlines())

    # Bare repository must be initialized prior to setting other git env vars
    subprocess.check_output(['git', 'init', '--bare', 'plugins'], cwd=repo_dir,
                            env=my_env)

    my_env['GIT_DIR'] = os.path.join(repo_dir, 'plugins')
    my_env['GIT_WORK_TREE'] = repo_dir
    my_env['GIT_INDEX_FILE'] = os.path.join(repo_dir, 'scratch-index')
    repo_initialization = (f'cp -r {plugins_path}/* .;'
                           'git add --all;'
                           'git commit -m "initial commit - autogenerated by test_reckless.py";')
    tag_and_update = ('git tag v1;'
                      "sed -i 's/v1/v2/g' testplugpass/testplugpass.py;"
                      'git add testplugpass/testplugpass.py;'
                      'git commit -m "update to v2";'
                      'git tag v2;')
    subprocess.check_output([repo_initialization], env=my_env, shell=True,
                            cwd=repo_dir)
    subprocess.check_output([tag_and_update], env=my_env,
                            shell=True, cwd=repo_dir)
    del my_env['HOME']
    del my_env['GIT_DIR']
    del my_env['GIT_WORK_TREE']
    del my_env['GIT_INDEX_FILE']
    # We also need the github api data for the repo which will be served via http
    shutil.copyfile(str(FILE_PATH / 'data/recklessrepo/rkls_api_lightningd_plugins.json'), os.path.join(directory, 'rkls_api_lightningd_plugins.json'))
    yield
    server.terminate()


def reckless(cmds: list, dir: PosixPath = None,
             autoconfirm=True, timeout: int = 15):
    '''Call the reckless executable, optionally with a directory.'''
    if dir is not None:
        cmds.insert(0, "-l")
        cmds.insert(1, str(dir))
    cmds.insert(0, "tools/reckless")
    r = subprocess.run(cmds, capture_output=True, encoding='utf-8', env=my_env,
                       input='Y\n')
    print(" ".join(r.args), "\n")
    print("***RECKLESS STDOUT***")
    for l in r.stdout.splitlines():
        print(l)
    print('\n')
    print("***RECKLESS STDERR***")
    for l in r.stderr.splitlines():
        print(l)
    print('\n')
    return r


def get_reckless_node(node_factory):
    '''This may be unnecessary, but a preconfigured lightning dir
    is useful for reckless testing.'''
    node = node_factory.get_node(options={}, start=False)
    return node


def check_stderr(stderr):
    def output_okay(out):
        for warning in ['[notice]', 'WARNING:', 'npm WARN',
                        'npm notice', 'DEPRECATION:', 'Creating virtualenv']:
            if out.startswith(warning):
                return True
        return False
    for e in stderr.splitlines():
        if len(e) < 1:
            continue
        # Don't err on verbosity from pip, npm
        assert output_okay(e)


def test_basic_help():
    '''Validate that argparse provides basic help info.
    This requires no config options passed to reckless.'''
    r = reckless(["-h"])
    assert r.returncode == 0
    assert "positional arguments:" in r.stdout.splitlines()
    assert "options:" in r.stdout.splitlines() or "optional arguments:" in r.stdout.splitlines()


def test_contextual_help(node_factory):
    n = get_reckless_node(node_factory)
    for subcmd in ['install', 'uninstall', 'search',
                   'enable', 'disable', 'source']:
        r = reckless([subcmd, "-h"], dir=n.lightning_dir)
        assert r.returncode == 0
        assert "positional arguments:" in r.stdout.splitlines()


def test_sources(node_factory):
    """add additional sources and search through them"""
    n = get_reckless_node(node_factory)
    r = reckless(["source", "-h"], dir=n.lightning_dir)
    assert r.returncode == 0
    r = reckless(["source", "list"], dir=n.lightning_dir)
    print(r.stdout)
    assert r.returncode == 0
    print(n.lightning_dir)
    reckless_dir = Path(n.lightning_dir) / 'reckless'
    print(dir(reckless_dir))
    assert (reckless_dir / '.sources').exists()
    print(os.listdir(reckless_dir))
    print(reckless_dir / '.sources')
    r = reckless([f"--network={NETWORK}", "-v", "source", "add",
                  "tests/data/recklessrepo/lightningd/testplugfail"],
                 dir=n.lightning_dir)
    r = reckless([f"--network={NETWORK}", "-v", "source", "add",
                  "tests/data/recklessrepo/lightningd/testplugpass"],
                 dir=n.lightning_dir)
    with open(reckless_dir / '.sources') as sources:
        contents = [c.strip() for c in sources.readlines()]
        print('contents:', contents)
        assert 'https://github.com/lightningd/plugins' in contents
        assert "tests/data/recklessrepo/lightningd/testplugfail" in contents
        assert "tests/data/recklessrepo/lightningd/testplugpass" in contents
    r = reckless([f"--network={NETWORK}", "-v", "source", "remove",
                  "tests/data/recklessrepo/lightningd/testplugfail"],
                 dir=n.lightning_dir)
    with open(reckless_dir / '.sources') as sources:
        contents = [c.strip() for c in sources.readlines()]
        print('contents:', contents)
        assert "tests/data/recklessrepo/lightningd/testplugfail" not in contents
        assert "tests/data/recklessrepo/lightningd/testplugpass" in contents


def test_search(node_factory):
    """add additional sources and search through them"""
    n = get_reckless_node(node_factory)
    r = reckless([f"--network={NETWORK}", "search", "testplugpass"], dir=n.lightning_dir)
    assert r.returncode == 0
    assert 'found testplugpass in source: https://github.com/lightningd/plugins' in r.stdout


@unittest.skipIf(VALGRIND, "virtual environment triggers memleak detection")
@unittest.skipIf(os.getenv('SUBDAEMON').startswith('hsmd:remote_hsmd'), "no canned github server in gitlab CI")
def test_install(node_factory):
    """test search, git clone, and installation to folder."""
    n = get_reckless_node(node_factory)
    r = reckless([f"--network={NETWORK}", "-v", "install", "testplugpass"], dir=n.lightning_dir)
    assert r.returncode == 0
    assert 'dependencies installed successfully' in r.stdout
    assert 'plugin installed:' in r.stdout
    assert 'testplugpass enabled' in r.stdout
    check_stderr(r.stderr)
    plugin_path = Path(n.lightning_dir) / 'reckless/testplugpass'
    print(plugin_path)
    assert os.path.exists(plugin_path)


@unittest.skipIf(VALGRIND, "virtual environment triggers memleak detection")
@unittest.skipIf(os.getenv('SUBDAEMON').startswith('hsmd:remote_hsmd'), "no canned github server in gitlab CI")
def test_poetry_install(node_factory):
    """test search, git clone, and installation to folder."""
    n = get_reckless_node(node_factory)
    r = reckless([f"--network={NETWORK}", "-v", "install", "testplugpyproj"], dir=n.lightning_dir)
    assert r.returncode == 0
    assert 'dependencies installed successfully' in r.stdout
    assert 'plugin installed:' in r.stdout
    assert 'testplugpyproj enabled' in r.stdout
    check_stderr(r.stderr)
    plugin_path = Path(n.lightning_dir) / 'reckless/testplugpyproj'
    print(plugin_path)
    assert os.path.exists(plugin_path)
    n.start()
    print(n.rpc.testmethod())
    assert n.daemon.is_in_log(r'plugin-manager: started\([0-9].*\) /tmp/ltests-[a-z0-9_].*/test_poetry_install_1/lightning-1/reckless/testplugpyproj/testplugpyproj.py')
    assert n.rpc.testmethod() == 'I live.'


@unittest.skipIf(VALGRIND, "virtual environment triggers memleak detection")
@unittest.skipIf(os.getenv('SUBDAEMON').startswith('hsmd:remote_hsmd'), "no canned github server in gitlab CI")
def test_local_dir_install(node_factory):
    """Test search and install from local directory source."""
    n = get_reckless_node(node_factory)
    n.start()
    r = reckless([f"--network={NETWORK}", "-v", "source", "add",
                  "tests/data/recklessrepo/lightningd/testplugpass"],
                 dir=n.lightning_dir)
    assert r.returncode == 0
    r = reckless([f"--network={NETWORK}", "-v", "install", "testplugpass"], dir=n.lightning_dir)
    assert r.returncode == 0
    assert 'testplugpass enabled' in r.stdout
    plugin_path = Path(n.lightning_dir) / 'reckless/testplugpass'
    print(plugin_path)
    assert os.path.exists(plugin_path)


@unittest.skipIf(VALGRIND, "virtual environment triggers memleak detection")
@unittest.skipIf(os.getenv('SUBDAEMON').startswith('hsmd:remote_hsmd'), "no canned github server in gitlab CI")
def test_disable_enable(node_factory):
    """test search, git clone, and installation to folder."""
    n = get_reckless_node(node_factory)
    # Test case-insensitive search as well
    r = reckless([f"--network={NETWORK}", "-v", "install", "testPlugPass"],
                 dir=n.lightning_dir)
    assert r.returncode == 0
    assert 'dependencies installed successfully' in r.stdout
    assert 'plugin installed:' in r.stdout
    assert 'testplugpass enabled' in r.stdout
    check_stderr(r.stderr)
    plugin_path = Path(n.lightning_dir) / 'reckless/testplugpass'
    print(plugin_path)
    assert os.path.exists(plugin_path)
    r = reckless([f"--network={NETWORK}", "-v", "disable", "testPlugPass"],
                 dir=n.lightning_dir)
    assert r.returncode == 0
    n.start()
    # Should find it with or without the file extension
    r = reckless([f"--network={NETWORK}", "-v", "enable", "testplugpass.py"],
                 dir=n.lightning_dir)
    assert r.returncode == 0
    assert 'testplugpass enabled' in r.stdout
    test_plugin = {'name': str(plugin_path / 'testplugpass.py'),
                   'active': True, 'dynamic': True}
    time.sleep(1)
    print(n.rpc.plugin_list()['plugins'])
    assert test_plugin in n.rpc.plugin_list()['plugins']


@unittest.skipIf(VALGRIND, "virtual environment triggers memleak detection")
@unittest.skipIf(os.getenv('SUBDAEMON').startswith('hsmd:remote_hsmd'), "no canned github server in gitlab CI")
@unittest.skipIf(VALGRIND, "virtual environment triggers memleak detection")
def test_tag_install(node_factory):
    "install a plugin from a specific commit hash or tag"
    node = get_reckless_node(node_factory)
    node.start()
    r = reckless([f"--network={NETWORK}", "-v", "install", "testPlugPass"],
                 dir=node.lightning_dir)
    assert r.returncode == 0
    metadata = node.lightning_dir / "reckless/testplugpass/.metadata"
    with open(metadata, "r") as md:
        header = ''
        for line in md.readlines():
            line = line.strip()
            if header == 'requested commit':
                assert line == 'None'
            header = line
    # should install v2 (latest) without specifying
    version = node.rpc.gettestplugversion()
    assert version == 'v2'
    r = reckless([f"--network={NETWORK}", "-v", "uninstall", "testplugpass"],
                 dir=node.lightning_dir)
    r = reckless([f"--network={NETWORK}", "-v", "install", "testplugpass@v1"],
                 dir=node.lightning_dir)
    assert r.returncode == 0
    # v1 should now be checked out.
    version = node.rpc.gettestplugversion()
    assert version == 'v1'
    installed_path = Path(node.lightning_dir) / 'reckless/testplugpass'
    assert installed_path.is_dir()
    with open(metadata, "r") as md:
        header = ''
        for line in md.readlines():
            line = line.strip()
            if header == 'requested commit':
                assert line == 'v1'
            header = line
