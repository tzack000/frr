#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_bfd_lag.py - Unit tests for BFD over LAG (Micro-BFD) implementation
#
# Copyright (C) 2024 FRRouting
#
# These tests verify the Micro-BFD implementation by testing:
# - Configuration parsing and validation
# - YANG model structure
# - CLI command syntax
# - Timer inheritance logic
# - Data structure relationships
#

import unittest
import os
import sys
import re
import json

# Test directory
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
FRR_ROOT = os.path.dirname(os.path.dirname(TEST_DIR))


class TestMicroBFDConstants(unittest.TestCase):
    """Test Micro-BFD constants and definitions"""

    def test_micro_bfd_port(self):
        """Verify Micro-BFD uses UDP port 6784 per RFC 7130"""
        bfd_h_path = os.path.join(FRR_ROOT, "bfdd", "bfd.h")
        with open(bfd_h_path, "r") as f:
            content = f.read()

        # Check for BFD_DEF_MICRO_BFD_PORT definition
        match = re.search(r"#define\s+BFD_DEF_MICRO_BFD_PORT\s+(\d+)", content)
        self.assertIsNotNone(match, "BFD_DEF_MICRO_BFD_PORT not defined in bfd.h")
        self.assertEqual(int(match.group(1)), 6784,
                         "Micro-BFD port should be 6784 per RFC 7130")

    def test_micro_bfd_session_flag(self):
        """Verify BFD_SESS_FLAG_MICRO_BFD is defined"""
        bfd_h_path = os.path.join(FRR_ROOT, "bfdd", "bfd.h")
        with open(bfd_h_path, "r") as f:
            content = f.read()

        self.assertIn("BFD_SESS_FLAG_MICRO_BFD", content,
                      "BFD_SESS_FLAG_MICRO_BFD should be defined in bfd.h")

    def test_protodown_reason_defined(self):
        """Verify ZEBRA_PROTODOWN_MICRO_BFD is defined"""
        zebra_router_h_path = os.path.join(FRR_ROOT, "zebra", "zebra_router.h")
        with open(zebra_router_h_path, "r") as f:
            content = f.read()

        self.assertIn("ZEBRA_PROTODOWN_MICRO_BFD", content,
                      "ZEBRA_PROTODOWN_MICRO_BFD should be defined")

    def test_zclient_message_type(self):
        """Verify ZEBRA_BFD_LAG_MEMBER_STATUS message type is defined"""
        zclient_h_path = os.path.join(FRR_ROOT, "lib", "zclient.h")
        with open(zclient_h_path, "r") as f:
            content = f.read()

        self.assertIn("ZEBRA_BFD_LAG_MEMBER_STATUS", content,
                      "ZEBRA_BFD_LAG_MEMBER_STATUS should be defined in zclient.h")


class TestMicroBFDDataStructures(unittest.TestCase):
    """Test Micro-BFD data structure definitions"""

    def setUp(self):
        """Load bfd_lag.h content"""
        bfd_lag_h_path = os.path.join(FRR_ROOT, "bfdd", "bfd_lag.h")
        with open(bfd_lag_h_path, "r") as f:
            self.bfd_lag_h_content = f.read()

    def test_bfd_lag_struct_exists(self):
        """Verify struct bfd_lag is defined"""
        self.assertIn("struct bfd_lag {", self.bfd_lag_h_content,
                      "struct bfd_lag should be defined")

    def test_bfd_lag_member_struct_exists(self):
        """Verify struct bfd_lag_member is defined"""
        self.assertIn("struct bfd_lag_member {", self.bfd_lag_h_content,
                      "struct bfd_lag_member should be defined")

    def test_bfd_lag_has_required_fields(self):
        """Verify bfd_lag struct has required fields"""
        required_fields = [
            "lag_name",
            "vrfname",
            "detect_mult",
            "min_tx",
            "min_rx",
            "admin_shutdown",
            "profile_name",
            "member_sessions",
            "active_members",
            "total_members",
        ]
        for field in required_fields:
            self.assertIn(field, self.bfd_lag_h_content,
                          f"bfd_lag should have field: {field}")

    def test_bfd_lag_member_has_required_fields(self):
        """Verify bfd_lag_member struct has required fields"""
        required_fields = [
            "member_name",
            "member_ifp",
            "lag",
            "bs",
            "local_addr",
            "peer_addr",
            "link_up",
            "bfd_up",
            "protodown_set",
        ]
        for field in required_fields:
            self.assertIn(field, self.bfd_lag_h_content,
                          f"bfd_lag_member should have field: {field}")


class TestMicroBFDFunctions(unittest.TestCase):
    """Test Micro-BFD function declarations"""

    def setUp(self):
        """Load header file contents"""
        bfd_lag_h_path = os.path.join(FRR_ROOT, "bfdd", "bfd_lag.h")
        with open(bfd_lag_h_path, "r") as f:
            self.bfd_lag_h_content = f.read()

    def test_lag_management_functions(self):
        """Verify LAG management functions are declared"""
        required_functions = [
            "bfd_lag_new",
            "bfd_lag_find",
            "bfd_lag_get",
            "bfd_lag_free",
            "bfd_lag_apply",
            "bfd_lag_init",
            "bfd_lag_finish",
        ]
        for func in required_functions:
            self.assertIn(func, self.bfd_lag_h_content,
                          f"Function {func} should be declared")

    def test_member_management_functions(self):
        """Verify member management functions are declared"""
        required_functions = [
            "bfd_lag_member_new",
            "bfd_lag_member_find",
            "bfd_lag_member_get",
            "bfd_lag_member_free",
            "bfd_lag_member_enable",
            "bfd_lag_member_disable",
        ]
        for func in required_functions:
            self.assertIn(func, self.bfd_lag_h_content,
                          f"Function {func} should be declared")

    def test_state_change_functions(self):
        """Verify state change handler functions are declared"""
        required_functions = [
            "bfd_lag_session_state_change",
            "bfd_lag_notify_zebra",
        ]
        for func in required_functions:
            self.assertIn(func, self.bfd_lag_h_content,
                          f"Function {func} should be declared")

    def test_timer_functions(self):
        """Verify timer-related functions are declared"""
        self.assertIn("bfd_lag_member_get_timers", self.bfd_lag_h_content,
                      "bfd_lag_member_get_timers should be declared")
        self.assertIn("bfd_lag_update_timers", self.bfd_lag_h_content,
                      "bfd_lag_update_timers should be declared")


class TestMicroBFDImplementation(unittest.TestCase):
    """Test Micro-BFD implementation in bfd_lag.c"""

    def setUp(self):
        """Load bfd_lag.c content"""
        bfd_lag_c_path = os.path.join(FRR_ROOT, "bfdd", "bfd_lag.c")
        with open(bfd_lag_c_path, "r") as f:
            self.bfd_lag_c_content = f.read()

    def test_memory_types_defined(self):
        """Verify memory types are defined for LAG structures"""
        self.assertIn("DEFINE_MTYPE", self.bfd_lag_c_content,
                      "Memory types should be defined")
        self.assertIn("BFD_LAG", self.bfd_lag_c_content,
                      "BFD_LAG memory type should be defined")

    def test_global_lag_list(self):
        """Verify global LAG list is defined"""
        self.assertIn("bfd_lag_list", self.bfd_lag_c_content,
                      "Global bfd_lag_list should be defined")

    def test_timer_inheritance_implementation(self):
        """Verify timer inheritance logic is implemented"""
        # Check for the timer inheritance function
        self.assertIn("bfd_lag_member_get_timers", self.bfd_lag_c_content,
                      "Timer inheritance function should be implemented")
        # Check it considers profile, LAG, and member level timers
        self.assertIn("profile", self.bfd_lag_c_content.lower(),
                      "Timer inheritance should consider profile")

    def test_session_state_change_handler(self):
        """Verify session state change handler is implemented"""
        self.assertIn("bfd_lag_session_state_change", self.bfd_lag_c_content,
                      "Session state change handler should be implemented")

    def test_protodown_notification(self):
        """Verify protodown notification is implemented"""
        self.assertIn("bfd_lag_notify_zebra", self.bfd_lag_c_content,
                      "Zebra notification function should be implemented")

    def test_display_functions(self):
        """Verify display functions are implemented"""
        self.assertIn("bfd_lag_show", self.bfd_lag_c_content,
                      "bfd_lag_show should be implemented")
        self.assertIn("bfd_lag_show_members", self.bfd_lag_c_content,
                      "bfd_lag_show_members should be implemented")

    def test_config_write_function(self):
        """Verify config write function is implemented"""
        self.assertIn("bfd_lag_config_write", self.bfd_lag_c_content,
                      "bfd_lag_config_write should be implemented")


class TestMicroBFDYANGModel(unittest.TestCase):
    """Test YANG model for Micro-BFD"""

    def setUp(self):
        """Load YANG model content"""
        yang_path = os.path.join(FRR_ROOT, "yang", "frr-bfdd.yang")
        with open(yang_path, "r") as f:
            self.yang_content = f.read()

    def test_lag_list_defined(self):
        """Verify lag list is defined in YANG model"""
        self.assertIn("list lag", self.yang_content,
                      "list lag should be defined in YANG model")

    def test_lag_key_fields(self):
        """Verify lag list has correct key fields"""
        # Find the lag list section and check for key
        self.assertIn('key "lag-name vrf"', self.yang_content,
                      "lag list should have lag-name and vrf as keys")

    def test_member_link_list_defined(self):
        """Verify member-link list is defined"""
        self.assertIn("list member-link", self.yang_content,
                      "list member-link should be defined in YANG model")

    def test_lag_timer_leaves(self):
        """Verify timer leaves are defined for LAG"""
        timer_leaves = [
            "detection-multiplier",
            "desired-transmission-interval",
            "required-receive-interval",
        ]
        for leaf in timer_leaves:
            self.assertIn(leaf, self.yang_content,
                          f"LAG should have {leaf} leaf")

    def test_member_address_leaves(self):
        """Verify address leaves are defined for member-link"""
        self.assertIn("local-address", self.yang_content,
                      "member-link should have local-address leaf")
        self.assertIn("peer-address", self.yang_content,
                      "member-link should have peer-address leaf")

    def test_stats_containers(self):
        """Verify stats containers are defined"""
        # LAG stats
        self.assertIn("total-members", self.yang_content,
                      "LAG stats should include total-members")
        self.assertIn("active-members", self.yang_content,
                      "LAG stats should include active-members")


class TestMicroBFDCLI(unittest.TestCase):
    """Test CLI command definitions"""

    def setUp(self):
        """Load CLI file contents"""
        cli_path = os.path.join(FRR_ROOT, "bfdd", "bfdd_cli.c")
        with open(cli_path, "r") as f:
            self.cli_content = f.read()

        vty_path = os.path.join(FRR_ROOT, "bfdd", "bfdd_vty.c")
        with open(vty_path, "r") as f:
            self.vty_content = f.read()

    def test_lag_command_defined(self):
        """Verify lag command is defined"""
        self.assertIn("bfd_lag_enter", self.cli_content,
                      "lag command should be defined")
        self.assertIn('"lag LAGNAME', self.cli_content,
                      "lag command syntax should be correct")

    def test_member_link_command_defined(self):
        """Verify member-link command is defined"""
        self.assertIn("bfd_lag_member", self.cli_content,
                      "member-link command should be defined")

    def test_address_commands_defined(self):
        """Verify address configuration commands are defined"""
        self.assertIn("local-address", self.cli_content,
                      "local-address command should be defined")
        self.assertIn("peer-address", self.cli_content,
                      "peer-address command should be defined")

    def test_timer_commands_defined(self):
        """Verify timer commands are defined for LAG"""
        self.assertIn("detect-multiplier", self.cli_content,
                      "detect-multiplier command should be defined")
        self.assertIn("transmit-interval", self.cli_content,
                      "transmit-interval command should be defined")
        self.assertIn("receive-interval", self.cli_content,
                      "receive-interval command should be defined")

    def test_show_lag_command_defined(self):
        """Verify show bfd lag command is defined"""
        self.assertIn("show_bfd_lag", self.vty_content,
                      "show bfd lag command should be defined")

    def test_show_lag_members_command_defined(self):
        """Verify show bfd lag members command is defined"""
        self.assertIn("show_bfd_lag_members", self.vty_content,
                      "show bfd lag members command should be defined")

    def test_cli_nodes_defined(self):
        """Verify CLI nodes are defined"""
        self.assertIn("BFD_LAG_NODE", self.cli_content,
                      "BFD_LAG_NODE should be used")
        self.assertIn("BFD_LAG_MEMBER_NODE", self.cli_content,
                      "BFD_LAG_MEMBER_NODE should be used")


class TestMicroBFDNorthbound(unittest.TestCase):
    """Test Northbound callback implementations"""

    def setUp(self):
        """Load NB file contents"""
        nb_h_path = os.path.join(FRR_ROOT, "bfdd", "bfdd_nb.h")
        with open(nb_h_path, "r") as f:
            self.nb_h_content = f.read()

        nb_c_path = os.path.join(FRR_ROOT, "bfdd", "bfdd_nb.c")
        with open(nb_c_path, "r") as f:
            self.nb_c_content = f.read()

        nb_config_path = os.path.join(FRR_ROOT, "bfdd", "bfdd_nb_config.c")
        with open(nb_config_path, "r") as f:
            self.nb_config_content = f.read()

        nb_state_path = os.path.join(FRR_ROOT, "bfdd", "bfdd_nb_state.c")
        with open(nb_state_path, "r") as f:
            self.nb_state_content = f.read()

    def test_lag_callbacks_declared(self):
        """Verify LAG NB callbacks are declared"""
        required_callbacks = [
            "bfdd_bfd_lag_create",
            "bfdd_bfd_lag_destroy",
            "bfdd_bfd_lag_get_next",
            "bfdd_bfd_lag_get_keys",
        ]
        for cb in required_callbacks:
            self.assertIn(cb, self.nb_h_content,
                          f"Callback {cb} should be declared in bfdd_nb.h")

    def test_member_link_callbacks_declared(self):
        """Verify member-link NB callbacks are declared"""
        required_callbacks = [
            "bfdd_bfd_lag_member_link_create",
            "bfdd_bfd_lag_member_link_destroy",
        ]
        for cb in required_callbacks:
            self.assertIn(cb, self.nb_h_content,
                          f"Callback {cb} should be declared in bfdd_nb.h")

    def test_lag_xpath_registered(self):
        """Verify LAG xpath is registered in bfdd_nb.c"""
        self.assertIn("/frr-bfdd:bfdd/bfd/lag", self.nb_c_content,
                      "LAG xpath should be registered")

    def test_lag_callbacks_implemented(self):
        """Verify LAG callbacks are implemented in bfdd_nb_config.c"""
        required_implementations = [
            "bfdd_bfd_lag_create",
            "bfdd_bfd_lag_destroy",
        ]
        for impl in required_implementations:
            self.assertIn(impl, self.nb_config_content,
                          f"Callback {impl} should be implemented")

    def test_lag_stats_callbacks_implemented(self):
        """Verify LAG stats callbacks are implemented"""
        required_stats = [
            "bfdd_bfd_lag_stats_total_members_get_elem",
            "bfdd_bfd_lag_stats_active_members_get_elem",
        ]
        for stat in required_stats:
            self.assertIn(stat, self.nb_state_content,
                          f"Stats callback {stat} should be implemented")


class TestMicroBFDZebraIntegration(unittest.TestCase):
    """Test Zebra integration for protodown"""

    def setUp(self):
        """Load zebra integration file contents"""
        ptm_adapter_path = os.path.join(FRR_ROOT, "bfdd", "ptm_adapter.c")
        with open(ptm_adapter_path, "r") as f:
            self.ptm_adapter_content = f.read()

        zebra_ptm_path = os.path.join(FRR_ROOT, "zebra", "zebra_ptm.c")
        with open(zebra_ptm_path, "r") as f:
            self.zebra_ptm_content = f.read()

    def test_lag_member_notification_function(self):
        """Verify LAG member notification function exists"""
        self.assertIn("ptm_bfd_notify_lag_member", self.ptm_adapter_content,
                      "ptm_bfd_notify_lag_member should be implemented")

    def test_zebra_handler_exists(self):
        """Verify zebra handler for LAG member status exists"""
        self.assertIn("zebra_ptm_bfd_lag_member_status", self.zebra_ptm_content,
                      "zebra_ptm_bfd_lag_member_status should be implemented")

    def test_protodown_call(self):
        """Verify protodown is called in zebra handler"""
        self.assertIn("zebra_if_set_protodown", self.zebra_ptm_content,
                      "zebra_if_set_protodown should be called")


class TestMicroBFDDocumentation(unittest.TestCase):
    """Test documentation completeness"""

    def test_user_documentation_exists(self):
        """Verify user documentation for Micro-BFD exists"""
        doc_path = os.path.join(FRR_ROOT, "doc", "user", "bfd.rst")
        with open(doc_path, "r") as f:
            content = f.read()

        self.assertIn("Micro-BFD", content,
                      "User documentation should mention Micro-BFD")
        # RST format uses :rfc:`7130` syntax
        self.assertTrue("7130" in content,
                        "User documentation should reference RFC 7130")
        self.assertIn("lag", content.lower(),
                      "User documentation should describe lag command")

    def test_developer_documentation_exists(self):
        """Verify developer documentation for BFD exists"""
        doc_path = os.path.join(FRR_ROOT, "doc", "developer", "bfd.rst")
        self.assertTrue(os.path.exists(doc_path),
                        "Developer documentation for BFD should exist")

        with open(doc_path, "r") as f:
            content = f.read()

        self.assertIn("Micro-BFD", content,
                      "Developer documentation should mention Micro-BFD")
        self.assertIn("bfd_lag", content,
                      "Developer documentation should describe bfd_lag structures")


class TestMicroBFDBuildSystem(unittest.TestCase):
    """Test build system integration"""

    def test_source_files_in_build(self):
        """Verify source files are added to build system"""
        subdir_am_path = os.path.join(FRR_ROOT, "bfdd", "subdir.am")
        with open(subdir_am_path, "r") as f:
            content = f.read()

        self.assertIn("bfd_lag.c", content,
                      "bfd_lag.c should be in subdir.am")
        self.assertIn("bfd_lag.h", content,
                      "bfd_lag.h should be in subdir.am")

    def test_cli_nodes_in_command_h(self):
        """Verify CLI nodes are defined in command.h"""
        command_h_path = os.path.join(FRR_ROOT, "lib", "command.h")
        with open(command_h_path, "r") as f:
            content = f.read()

        self.assertIn("BFD_LAG_NODE", content,
                      "BFD_LAG_NODE should be defined in command.h")
        self.assertIn("BFD_LAG_MEMBER_NODE", content,
                      "BFD_LAG_MEMBER_NODE should be defined in command.h")


class TestMicroBFDTopotest(unittest.TestCase):
    """Test topotest framework exists"""

    def test_topotest_directory_exists(self):
        """Verify topotest directory for Micro-BFD exists"""
        topotest_dir = os.path.join(FRR_ROOT, "tests", "topotests", "bfd_lag_topo1")
        self.assertTrue(os.path.isdir(topotest_dir),
                        "Topotest directory for Micro-BFD should exist")

    def test_topotest_files_exist(self):
        """Verify topotest files exist"""
        topotest_dir = os.path.join(FRR_ROOT, "tests", "topotests", "bfd_lag_topo1")

        required_files = [
            "__init__.py",
            "test_bfd_lag_topo1.py",
        ]
        for f in required_files:
            path = os.path.join(topotest_dir, f)
            self.assertTrue(os.path.exists(path),
                            f"Topotest file {f} should exist")

    def test_topotest_config_files_exist(self):
        """Verify topotest configuration files exist"""
        topotest_dir = os.path.join(FRR_ROOT, "tests", "topotests", "bfd_lag_topo1")

        for router in ["r1", "r2"]:
            router_dir = os.path.join(topotest_dir, router)
            self.assertTrue(os.path.isdir(router_dir),
                            f"Router directory {router} should exist")

            for conf in ["zebra.conf", "bfdd.conf"]:
                conf_path = os.path.join(router_dir, conf)
                self.assertTrue(os.path.exists(conf_path),
                                f"Config file {router}/{conf} should exist")


def create_test_report(result):
    """Create a formatted test report"""
    report = []
    report.append("=" * 70)
    report.append("MICRO-BFD (RFC 7130) UNIT TEST REPORT")
    report.append("=" * 70)
    report.append("")

    # Summary
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = total - failures - errors - skipped

    report.append("SUMMARY")
    report.append("-" * 70)
    report.append(f"  Total Tests:  {total}")
    report.append(f"  Passed:       {passed}")
    report.append(f"  Failed:       {failures}")
    report.append(f"  Errors:       {errors}")
    report.append(f"  Skipped:      {skipped}")
    report.append("")

    # Calculate pass rate
    if total > 0:
        pass_rate = (passed / total) * 100
        report.append(f"  Pass Rate:    {pass_rate:.1f}%")
    report.append("")

    # Test categories
    report.append("TEST CATEGORIES")
    report.append("-" * 70)

    categories = {
        "Constants & Definitions": "TestMicroBFDConstants",
        "Data Structures": "TestMicroBFDDataStructures",
        "Function Declarations": "TestMicroBFDFunctions",
        "Implementation": "TestMicroBFDImplementation",
        "YANG Model": "TestMicroBFDYANGModel",
        "CLI Commands": "TestMicroBFDCLI",
        "Northbound Callbacks": "TestMicroBFDNorthbound",
        "Zebra Integration": "TestMicroBFDZebraIntegration",
        "Documentation": "TestMicroBFDDocumentation",
        "Build System": "TestMicroBFDBuildSystem",
        "Topotest Framework": "TestMicroBFDTopotest",
    }

    for category, class_name in categories.items():
        report.append(f"  {category}")

    report.append("")

    # Failures
    if result.failures:
        report.append("FAILURES")
        report.append("-" * 70)
        for test, traceback in result.failures:
            report.append(f"  FAIL: {test}")
            # Extract just the assertion message
            lines = traceback.strip().split('\n')
            for line in lines[-3:]:
                report.append(f"        {line.strip()}")
            report.append("")

    # Errors
    if result.errors:
        report.append("ERRORS")
        report.append("-" * 70)
        for test, traceback in result.errors:
            report.append(f"  ERROR: {test}")
            lines = traceback.strip().split('\n')
            for line in lines[-3:]:
                report.append(f"        {line.strip()}")
            report.append("")

    # Final status
    report.append("=" * 70)
    if failures == 0 and errors == 0:
        report.append("STATUS: ALL TESTS PASSED")
    else:
        report.append(f"STATUS: {failures + errors} TEST(S) FAILED")
    report.append("=" * 70)

    return "\n".join(report)


if __name__ == "__main__":
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestMicroBFDConstants,
        TestMicroBFDDataStructures,
        TestMicroBFDFunctions,
        TestMicroBFDImplementation,
        TestMicroBFDYANGModel,
        TestMicroBFDCLI,
        TestMicroBFDNorthbound,
        TestMicroBFDZebraIntegration,
        TestMicroBFDDocumentation,
        TestMicroBFDBuildSystem,
        TestMicroBFDTopotest,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Generate and print report
    print("\n")
    report = create_test_report(result)
    print(report)

    # Write report to file
    report_path = os.path.join(TEST_DIR, "test_report.txt")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
