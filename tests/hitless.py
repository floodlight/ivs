#!/usr/bin/env python
"""
This test verifies that an IVS started with the --hitless flag waits until it
receives a bsn_takeover message before revalidating the kernel flowtable.
"""
import subprocess
import logging
import time
import os
import signal
import sys

sys.path.insert(1, "submodules/loxigen-artifacts/pyloxi")
import loxi.of14 as ofp
import loxi.connection
from loxi.pp import pp

IVS = "./targets/ivs/build/gcc-local/bin/ivs"

logging.basicConfig(level=logging.INFO)

logfile = file("ivs.log", "w")
ivs = None

def start_ivs():
    global ivs
    logging.info("Starting IVS")
    ivs = subprocess.Popen(
        [IVS, '-v', '-l', '127.0.0.1:6634', '--hitless', '-V', '1.3'],
        stdout=logfile, stderr=logfile)

def insert_flows():
    logging.info("Inserting flows")
    cxn = loxi.connection.connect("127.0.0.1", port=6634)
    port_descs = cxn.transact_multipart(ofp.message.port_desc_stats_request())
    port_numbers = { x.name: x.port_no for x in port_descs }

    cxn.send(ofp.message.flow_add(
        match=ofp.match([
            ofp.oxm.in_port(port_numbers["test1"])]),
        instructions=[
            ofp.instruction.apply_actions([
                ofp.action.output(port_numbers["test2"])])]))
    cxn.send(ofp.message.flow_add(
        match=ofp.match([
            ofp.oxm.in_port(port_numbers["test2"])]),
        instructions=[
            ofp.instruction.apply_actions([
                ofp.action.output(port_numbers["test1"])])]))
    cxn.send(ofp.message.bsn_takeover())
    cxn.transact(ofp.message.barrier_request())

def cmd(*args):
    logging.debug("Running %s", ' '.join(args))
    subprocess.check_call(args)


subprocess.call(["ivs-ctl", "del-dp"])

try:
    if os.path.exists("/var/run/netns/test1"):
        cmd("ip", "netns", "delete", "test1")

    if os.path.exists("/var/run/netns/test2"):
        cmd("ip", "netns", "delete", "test2")

    start_ivs()

    cmd("ip", "netns", "add", "test1")
    cmd("ip", "netns", "add", "test2")

    cmd("ip", "link", "add", "name", "test1", "type", "veth", "peer", "name", "test1-peer")
    cmd("ip", "link", "set", "test1-peer", "up", "netns", "test1", "name", "eth0")
    cmd("ip", "netns", "exec", "test1", "ip", "addr", "add", "dev", "eth0", "192.168.248.1/24")

    cmd("ip", "link", "add", "name", "test2", "type", "veth", "peer", "name", "test2-peer")
    cmd("ip", "link", "set", "test2-peer", "up", "netns", "test2", "name", "eth0")
    cmd("ip", "netns", "exec", "test2", "ip", "addr", "add", "dev", "eth0", "192.168.248.2/24")

    cmd("ivs-ctl", "add-port", "test1")
    cmd("ivs-ctl", "add-port", "test2")

    insert_flows()

    logging.info("Normal ping")
    cmd("ip", "netns", "exec", "test1", "ping", "-c", "10", "-i", "0.1", "192.168.248.2")
    ivs.kill()

    logging.info("Pinging while IVS is dead")
    cmd("ip", "netns", "exec", "test1", "ping", "-c", "10", "-i", "0.1", "192.168.248.2")

    start_ivs()

    logging.info("Pinging after IVS has restarted but before takeover")
    cmd("ip", "netns", "exec", "test1", "ping", "-c", "10", "-i", "0.1", "192.168.248.2")

    insert_flows()

    logging.info("Pinging after takeover")
    cmd("ip", "netns", "exec", "test1", "ping", "-c", "10", "-i", "0.1", "192.168.248.2")
finally:
    if ivs:
        ivs.kill()

    if os.path.exists("/var/run/netns/test1"):
        cmd("ip", "netns", "delete", "test1")

    if os.path.exists("/var/run/netns/test2"):
        cmd("ip", "netns", "delete", "test2")
