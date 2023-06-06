from __future__ import print_function

import os
import rpyc
import signal
import threading
import time

import pytest
from multiprocessing import Process

import spytest
from spytest.dicts import SpyTestDict
from spytest import env

import utilities.common as utils

wa = SpyTestDict()
wa.parse_logs = []
wa.count = 0
wa.pwa = None
wa.pwa_support = False

# new batch implementation variables
wa.slave_index = 0
wa.debug_level = 1

def debug(*args, **kwargs):
    if wa.debug_level > 0:
        wa.trace(*args, **kwargs)

def trace(*args, **kwargs):
    msg = " ".join(map(str,args))
    print(msg)

wa.debug = debug
wa.trace = trace

class Node(object):
    def __init__(self, name):
        self.gateway = SpyTestDict()
        self.gateway.id = name
        self.shutting_down = False
        self.finished = False
        self.new_indexes = []

    def shutdown(self):
        self.finished = True

    def send_runtest_some(self, indexes):
        self.new_indexes = indexes

class BatchService(rpyc.Service):
    def __init__(self, config, logs_path):
        self.config = config
        self.logs_path = logs_path
        self.sched = None
        self.ready = False
        self.items = []
        self.item_names = []
        self.status = []
        self.slave_pids = {}
        self.nodes = {}

    def make_scheduler(self):
        if wa.pwa:
            debug("master: make_scheduler")
            self.sched = wa.pwa.make_scheduler(self.config, self.logs_path, wa.count)

    def set_items(self, items):
        self.items = items
        self.status = []
        self.item_names = []
        for item in items:
            self.status.append(0)
            self.item_names.append(item.name)
        self.ready = True

    def on_connect(self, conn):
        wa.debug("BatchService connected", conn)

    def on_disconnect(self, conn):
        wa.debug("BatchService disconnected", conn)

    def exposed_register(self, name):
        node = Node(name)
        self.nodes[name] = node
        if self.sched:
            self.sched.add_node(node)
            wa.debug("Node {} added".format(name))
        if len(self.nodes) < wa.count:
            wa.debug("More Nodes to be registered")
            return
        if wa.pwa:
            wa.pwa.configure_nodes(self.config, None)
            for node in self.nodes.values():
                wa.pwa.begin_node(node.gateway)
                wa.pwa.configure_node(node)
                self.sched.add_node_collection(node, self.item_names)
        if self.sched:
            self.sched.schedule()

    def exposed_shutdown(self):
        for pid in self.slave_pids:
            os.kill(pid, signal.SIGTERM)

    def exposed_is_ready(self, pid):
        if pid not in self.slave_pids:
            self.slave_pids[pid] = 0
        return self.ready

    def exposed_has_pending(self):
        for i in range(0, len(self.status)):
            if self.status[i] != 2:
                return True
        return False

    def exposed_finish_test(self, name, nodeid):
        if not nodeid:
            if wa.pwa:
                node = self.nodes[name]
                wa.pwa.finish_node(node, False, None)
        else:
            for i, ent in enumerate(self.items):
                if ent.nodeid == nodeid:
                    self.status[i] = 2

    def exposed_get_tests(self, name):
        node = self.nodes[name]
        if node.finished:
            wa.debug("BatchService: Node {} finished".format(name))
            return []
        if self.sched:
            self.sched.schedule()
            return node.new_indexes
        for i, _ in enumerate(self.items):
            if self.status[i] == 0:
                self.status[i] = 1
                nodeid = self.items[i].nodeid
                wa.debug("BatchService: gaving {} to Node {}".format(nodeid, name))
                return [nodeid]
        wa.debug("BatchService: No tests for Node {}".format(name))
        return []

class BatchMaster(object):
    def __init__(self, config, logs_path):
        self.config = config
        self.logs_path = logs_path
        self.service = BatchService(config, logs_path)
        self.port = 0
        self.server = None
        self.thread = None
        self.conn = None

    def _shutdown(self):
        if self.conn:
            getattr(self.conn.root, "shutdown")()
            time.sleep(5)
        os._exit(0)

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        wa.debug("master:", session, config, items)
        self.service.set_items(items)
        if not items:
            wa.debug("master: No Test Cases are Available")
            self._shutdown()

    @pytest.mark.trylast
    def pytest_sessionstart(self, session):
        wa.debug("master: pytest_sessionstart", session)
        self.server = rpyc.utils.server.ThreadedServer(self.service)
        self.port = self.server.port
        filename = os.path.join(self.logs_path, "batch.server")
        utils.write_file(filename, str(self.server.port))
        self.thread = threading.Thread(target=self.server.start)
        self.thread.start()

    def pytest_sessionfinish(self, session):
        wa.debug("master: pytest_sessionfinish", session)

    def pytest_runtestloop(self):
        self.service.make_scheduler()
        slaves_init(self.logs_path)
        try:
            self.conn = rpyc.connect("127.0.0.1", self.port)
            while 1:
                if not getattr(self.conn.root, "has_pending")():
                    break
                wa.debug("master: pytest_runtestloop")
                time.sleep(5)
        except KeyboardInterrupt:
            wa.trace("master: interrupted")
            self._shutdown()
        os._exit(0)

    def pytest_terminal_summary(self, terminalreporter):
        wa.debug("master: pytest_terminal_summary", terminalreporter)

class BatchSlave(object):

    def __init__(self, config, logs_path):
        self.config = config
        self.items = []
        self.logs_path = logs_path
        self.name = os.getenv("PYTEST_XDIST_WORKER")

    @pytest.mark.trylast
    def pytest_sessionstart(self, session):
        wa.debug("slave: pytest_sessionstart", session)

    def pytest_sessionfinish(self, session):
        wa.debug("slave: pytest_sessionfinish", session)

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        wa.debug("slave: pytest_collection_modifyitems", session, config, items)
        self.items = items

    def pytest_runtestloop(self):

        def search_nodeids(entries, nodeids):
            retval = []
            for ent in entries:
                for nodeid in nodeids:
                    if nodeid == ent.nodeid:
                        retval.append(ent)
            return retval

        def finish_test(item):
            nodeid = item.nodeid if item else None
            getattr(conn.root, "finish_test")(self.name, nodeid)

        def get_tests():
            while 1:
                nodeids = getattr(conn.root, "get_tests")(self.name)
                if not nodeids: break
                items = search_nodeids(self.items, nodeids)
                if items: return items
            return []

        # connect to batch server
        conn = None
        for _ in range(0, 10):
            try:
                filename = os.path.join(self.logs_path, "..", "batch.server")
                lines = utils.read_lines(filename)
                port = int(lines[0])
                conn = rpyc.connect("127.0.0.1", port)
                if conn and conn.root:
                    break
                time.sleep(2)
            except Exception as exp:
                print("connect to batch server", exp, filename, port)
                time.sleep(2)

        try:
            item_list = []

            # wait for master ready
            is_ready = getattr(conn.root, "is_ready")
            while not is_ready(os.getpid()):
                wa.trace("slave: waiting for master")
                time.sleep(2)

            # register with master
            getattr(conn.root, "register")(self.name)

            # get first items
            item_list = get_tests()

            while 1:
                # check if there is some thing to do
                if not item_list:
                    finish_test(None)
                    break

                # get next items
                if len(item_list) < 2:
                    item_list.extend(get_tests())

                # get the item and next for the current execution
                [item, nextitem] = [item_list.pop(0), None]
                if item_list: nextitem = item_list[-1]

                wa.debug("slave: pytest_runtestloop", item, nextitem)
                self.config.hook.pytest_runtest_protocol(item=item, nextitem=nextitem)
                finish_test(item)
        except KeyboardInterrupt:
            wa.trace("slave: interrupted")
        conn.close()
        wa.trace("")
        os._exit(0)

    def pytest_terminal_summary(self, terminalreporter):
        wa.debug("slave: pytest_terminal_summary", terminalreporter)

def get_impl_type():
    new_bach_run = env.get("SPYTEST_BATCH_RUN_NEW")
    if new_bach_run == "2": return 2
    return 1 if bool(new_bach_run) else 0

def shutdown():
    if get_impl_type() == 0:
        return
    if wa.server: wa.server.stop()
    if wa.service: wa.service.close()

def slave_main(index, testbed_file, logs_path):
    nodeid = "gw{}".format(index)
    os.environ["PYTEST_XDIST_WORKER"] = nodeid
    key = "SPYTEST_TESTBED_FILE_{}".format(nodeid)
    os.environ[key] = testbed_file
    os.environ["SPYTEST_TESTBED_FILE"] = testbed_file
    spytest.main.main(True)

def slave_start(testbed_file, logs_path):
    wa.debug("starting slave", testbed_file, wa.slave_index)
    p = Process(target=slave_main, args=(wa.slave_index,testbed_file,logs_path))
    p.start()
    wa.slave_index = wa.slave_index + 1

def slaves_init(logs_path):
    if get_impl_type() == 2:
        # present auto slave init
        return
    for index in range(0, wa.count):
        key = "SPYTEST_TESTBED_FILE_gw{}".format(index)
        slave_start(env.get(key), logs_path)

def configure(config, logs_path, is_slave, pwa=None):
    if get_impl_type() == 0:
        return
    if pwa and wa.pwa_support:
        wa.debug = pwa.debug
        wa.trace = pwa.trace
        wa.pwa = pwa
    if is_slave:
        wa.debug("============== batch configure slave =====================")
        slave = BatchSlave(config, logs_path)
        config.pluginmanager.register(slave, "batch.slave")
    else:
        wa.debug("============== batch configure master =====================")
        if "SPYTEST_BATCH_RUN" in os.environ:
            del os.environ["SPYTEST_BATCH_RUN"]
        master = BatchMaster(config, logs_path)
        config.pluginmanager.register(master, "batch.master")

def parse_args(count, l):
    if get_impl_type() == 0:
        return l
    wa.count = count
    return []

