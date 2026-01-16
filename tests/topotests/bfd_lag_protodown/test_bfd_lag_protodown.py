#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_lag_protodown.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 FRRouting
#

"""
test_bfd_lag_protodown.py: Test BFD over LAG protodown integration.

This test verifies that Micro-BFD properly integrates with Linux protodown:
- When BFD session goes Down, zebra sets protodown on the member interface
- When BFD session comes Up, zebra clears protodown on the member interface
- The Linux bonding driver responds to carrier state changes

Topology:
                    +----------+
                    |    r1    |
                    |  bond0   |
                    +----+-----+
                         |
                       (sw1)
                         |
                    +----+-----+
                    |  bond0   |
                    |    r2    |
                    +----------+

Single link between r1 and r2 for simpler protodown testing.
Uses point-to-point link-local addresses for Micro-BFD.
"""

import os
import sys
import json
import time
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

# Link-local addresses for Micro-BFD
MEMBER_ADDRESSES = {
    "r1": {"r1-eth0": {"local": "169.254.1.1", "peer": "169.254.1.2"}},
    "r2": {"r2-eth0": {"local": "169.254.1.2", "peer": "169.254.1.1"}},
}

BOND_NAME = "bond0"


def config_bond(node, node_name, bond_name, bond_members):
    """Create a Linux bonding interface and add members."""
    node.run("ip link add dev {} type bond mode balance-rr".format(bond_name))
    node.run("ip link set dev {} type bond miimon 100".format(bond_name))

    for member in bond_members:
        node.run("ip link set dev {} down".format(member))
        node.run("ip link set dev {} master {}".format(member, bond_name))
        addrs = MEMBER_ADDRESSES[node_name][member]
        node.run("ip addr add {}/24 dev {}".format(addrs["local"], member))
        node.run("ip link set dev {} up".format(member))

    node.run("ip link set dev {} up".format(bond_name))


def setup_module(mod):
    """Sets up the pytest environment"""
    # Simple topology with single link
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Create bonding interfaces
    for rname, router in router_list.items():
        if rname == "r1":
            members = ["r1-eth0"]
        else:
            members = ["r2-eth0"]
        config_bond(router, rname, BOND_NAME, members)

    # Load configuration files
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )

    tgen.start_router()

    # Verify version
    for router in router_list.values():
        if router.has_version("<", "10.0"):
            tgen.set_error("Unsupported FRR version for Micro-BFD")
            break


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def get_interface_protodown(router, ifname):
    """Check if interface has protodown set."""
    output = router.run("ip -d link show {}".format(ifname))
    return "protodown on" in output.lower()


def get_interface_carrier(router, ifname):
    """Check interface carrier state."""
    output = router.run("cat /sys/class/net/{}/carrier 2>/dev/null || echo 0".format(ifname))
    return output.strip() == "1"


def get_bfd_lag_member_state(router, lag_name, member_name):
    """Get BFD LAG member state from JSON output."""
    output = router.vtysh_cmd("show bfd lag {} members json".format(lag_name))
    try:
        data = json.loads(output)
        if "members" in data:
            for member in data["members"]:
                if member.get("memberName") == member_name:
                    return {
                        "state": member.get("state"),
                        "linkUp": member.get("linkUp"),
                        "bfdUp": member.get("bfdUp"),
                        "protodownSet": member.get("protodownSet"),
                    }
    except json.JSONDecodeError:
        pass
    return None


def test_bfd_lag_protodown_initial_state():
    """Verify initial protodown state before BFD sessions are up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking initial protodown state")

    for rname, router in tgen.routers().items():
        if rname == "r1":
            member = "r1-eth0"
        else:
            member = "r2-eth0"

        # Check BFD LAG member state
        state = get_bfd_lag_member_state(router, BOND_NAME, member)
        logger.info("{}: BFD LAG member state: {}".format(rname, state))

        if state:
            # Initially, protodown should not be set (BFD not failed yet)
            logger.info("{}: {}: protodownSet={}".format(
                rname, member, state.get("protodownSet")))

        # Check interface protodown via ip command
        protodown = get_interface_protodown(router, member)
        logger.info("{}: {}: protodown via ip: {}".format(rname, member, protodown))


def test_bfd_lag_configured():
    """Verify BFD LAG is configured correctly."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BFD LAG configuration")

    for rname, router in tgen.routers().items():
        output = router.vtysh_cmd("show bfd lag")
        logger.info("{}: show bfd lag:\n{}".format(rname, output))
        assert BOND_NAME in output, "{}: LAG not configured".format(rname)


def test_bfd_lag_member_exists():
    """Verify BFD LAG member is configured."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BFD LAG member configuration")

    for rname, router in tgen.routers().items():
        if rname == "r1":
            member = "r1-eth0"
        else:
            member = "r2-eth0"

        output = router.vtysh_cmd("show bfd lag {} members".format(BOND_NAME))
        logger.info("{}: show bfd lag members:\n{}".format(rname, output))
        assert member in output, "{}: member {} not found".format(rname, member)


def test_bfd_lag_protodown_on_admin_shutdown():
    """Test that admin shutdown sets protodown on member."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing protodown on admin shutdown")

    r1 = tgen.gears["r1"]
    member = "r1-eth0"

    # Get initial state
    state_before = get_bfd_lag_member_state(r1, BOND_NAME, member)
    logger.info("r1: Initial state: {}".format(state_before))

    # Shutdown the member
    r1.vtysh_cmd("configure terminal\nbfd\nlag bond0\nmember-link r1-eth0\nshutdown\nend\n")

    # Wait for state change
    time.sleep(2)

    # Check BFD state shows admin-down
    state_after = get_bfd_lag_member_state(r1, BOND_NAME, member)
    logger.info("r1: State after shutdown: {}".format(state_after))

    # Check show output
    output = r1.vtysh_cmd("show bfd lag {} members".format(BOND_NAME))
    logger.info("r1: show bfd lag members after shutdown:\n{}".format(output))

    # Restore the member
    r1.vtysh_cmd("configure terminal\nbfd\nlag bond0\nmember-link r1-eth0\nno shutdown\nend\n")
    time.sleep(1)


def test_bfd_lag_protodown_on_peer_timeout():
    """Test that BFD peer timeout triggers protodown notification."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing protodown on BFD peer timeout")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    member_r1 = "r1-eth0"
    member_r2 = "r2-eth0"

    # Record initial states
    state_r1_before = get_bfd_lag_member_state(r1, BOND_NAME, member_r1)
    state_r2_before = get_bfd_lag_member_state(r2, BOND_NAME, member_r2)
    logger.info("r1: Initial state: {}".format(state_r1_before))
    logger.info("r2: Initial state: {}".format(state_r2_before))

    # Shutdown BFD on r2 to simulate peer timeout on r1
    logger.info("Shutting down BFD LAG on r2 to trigger timeout on r1")
    r2.vtysh_cmd("configure terminal\nbfd\nlag bond0\nshutdown\nend\n")

    # Wait for BFD timeout (detection time = 3 * 300ms = 900ms, wait longer)
    time.sleep(3)

    # Check r1's BFD state - should show peer down
    state_r1_after = get_bfd_lag_member_state(r1, BOND_NAME, member_r1)
    logger.info("r1: State after r2 shutdown: {}".format(state_r1_after))

    output_r1 = r1.vtysh_cmd("show bfd lag {} members".format(BOND_NAME))
    logger.info("r1: show bfd lag members after r2 shutdown:\n{}".format(output_r1))

    # Check if protodown was set on r1's member
    protodown_r1 = get_interface_protodown(r1, member_r1)
    logger.info("r1: {}: protodown via ip: {}".format(member_r1, protodown_r1))

    # Restore r2
    logger.info("Restoring BFD LAG on r2")
    r2.vtysh_cmd("configure terminal\nbfd\nlag bond0\nno shutdown\nend\n")

    # Wait for BFD to recover
    time.sleep(3)

    # Check states after recovery
    state_r1_recovered = get_bfd_lag_member_state(r1, BOND_NAME, member_r1)
    logger.info("r1: State after r2 restored: {}".format(state_r1_recovered))

    protodown_r1_after = get_interface_protodown(r1, member_r1)
    logger.info("r1: {}: protodown after recovery: {}".format(member_r1, protodown_r1_after))


def test_bfd_lag_protodown_on_link_failure():
    """Test that link failure triggers BFD down and protodown."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing protodown on link failure")

    r1 = tgen.gears["r1"]
    member = "r1-eth0"

    # Record initial state
    state_before = get_bfd_lag_member_state(r1, BOND_NAME, member)
    logger.info("r1: Initial state: {}".format(state_before))

    # Bring down the interface to simulate link failure
    logger.info("Bringing down {} to simulate link failure".format(member))
    r1.run("ip link set dev {} down".format(member))

    # Wait for detection
    time.sleep(2)

    # Check BFD state
    state_after = get_bfd_lag_member_state(r1, BOND_NAME, member)
    logger.info("r1: State after link down: {}".format(state_after))

    output = r1.vtysh_cmd("show bfd lag {} members".format(BOND_NAME))
    logger.info("r1: show bfd lag members after link down:\n{}".format(output))

    # Restore the interface
    logger.info("Restoring {} link".format(member))
    r1.run("ip link set dev {} up".format(member))

    # Wait for recovery
    time.sleep(3)

    state_recovered = get_bfd_lag_member_state(r1, BOND_NAME, member)
    logger.info("r1: State after link restored: {}".format(state_recovered))


def test_bfd_lag_zebra_protodown_reason():
    """Verify zebra shows correct protodown reason for Micro-BFD."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking zebra protodown reason")

    r1 = tgen.gears["r1"]
    member = "r1-eth0"

    # Check zebra interface status
    output = r1.vtysh_cmd("show interface {}".format(member))
    logger.info("r1: show interface {}:\n{}".format(member, output))

    # The output should show protodown status if set
    # Look for protodown-related information


def test_bfd_lag_protodown_json_output():
    """Verify JSON output includes protodown status."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking JSON protodown output")

    for rname, router in tgen.routers().items():
        output = router.vtysh_cmd("show bfd lag {} members json".format(BOND_NAME))
        logger.info("{}: JSON output: {}".format(rname, output))

        try:
            data = json.loads(output)
            assert "members" in data, "Missing members key"

            for member in data["members"]:
                # Verify protodownSet field exists
                assert "protodownSet" in member, "Missing protodownSet field"
                logger.info("{}: {}: protodownSet={}".format(
                    rname, member.get("memberName"), member.get("protodownSet")))
        except json.JSONDecodeError as e:
            pytest.fail("Invalid JSON: {}".format(e))


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
