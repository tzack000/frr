.. _bfd-dev:

*************
BFD Internals
*************

This section documents the internal architecture of the BFD daemon (bfdd).

Micro-BFD Implementation
========================

Micro-BFD (RFC 7130) provides BFD sessions on LAG member links for rapid
failure detection. This section describes the implementation details.

Data Structures
---------------

``struct bfd_lag``
^^^^^^^^^^^^^^^^^^

Represents a LAG interface with Micro-BFD configuration. Located in
``bfdd/bfd_lag.h``.

Key fields:

- ``lag_name`` - LAG interface name (e.g., bond0)
- ``vrfname`` - VRF name
- ``detect_mult``, ``min_tx``, ``min_rx`` - BFD timers
- ``admin_shutdown`` - Administrative state
- ``member_sessions`` - List of member sessions
- ``active_members``, ``total_members`` - Member counts

``struct bfd_lag_member``
^^^^^^^^^^^^^^^^^^^^^^^^^

Represents a member link in the LAG. Located in ``bfdd/bfd_lag.h``.

Key fields:

- ``member_name`` - Member interface name
- ``lag`` - Parent LAG pointer
- ``bs`` - BFD session pointer
- ``local_addr``, ``peer_addr`` - Session addresses
- ``link_up``, ``bfd_up`` - Status flags
- ``protodown_set`` - Whether protodown is active

Key Functions
-------------

LAG Management (``bfdd/bfd_lag.c``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ``bfd_lag_new()`` / ``bfd_lag_free()`` - Create/destroy LAG
- ``bfd_lag_find()`` / ``bfd_lag_get()`` - Lookup LAG by name

Member Management
^^^^^^^^^^^^^^^^^

- ``bfd_lag_member_new()`` / ``bfd_lag_member_free()`` - Create/destroy member
- ``bfd_lag_member_enable()`` / ``bfd_lag_member_disable()`` - Enable/disable BFD session
- ``bfd_lag_member_get_timers()`` - Get effective timers with inheritance

State Change Handling
^^^^^^^^^^^^^^^^^^^^^

- ``bfd_lag_session_state_change()`` - Called when BFD session state changes
- ``bfd_lag_notify_zebra()`` - Send status to zebra for protodown

Zebra Integration
-----------------

The integration with zebra for protodown is handled through the
``ZEBRA_BFD_LAG_MEMBER_STATUS`` message.

Message Flow
^^^^^^^^^^^^

1. BFD session detects failure on a member link
2. bfdd calls ``bfd_lag_session_state_change()``
3. This calls ``bfd_lag_notify_zebra()``
4. Which calls ``ptm_bfd_notify_lag_member()`` in ``ptm_adapter.c``
5. Message is sent to zebra with interface name and BFD status
6. Zebra's ``zebra_ptm_bfd_lag_member_status()`` handler receives it
7. Calls ``zebra_if_set_protodown()`` with ``ZEBRA_PROTODOWN_MICRO_BFD``
8. Kernel sets protodown on the interface
9. Bonding driver removes the member from active aggregation

Message Format
^^^^^^^^^^^^^^

The ``ZEBRA_BFD_LAG_MEMBER_STATUS`` message contains:

- Interface name (IFNAMSIZ bytes)
- VRF name (VRF_NAMSIZ bytes)
- BFD status (1 byte: 1 = up, 0 = down)

YANG Model
----------

The YANG model is in ``yang/frr-bfdd.yang`` under ``/frr-bfdd:bfdd/bfd/lag``.

Structure::

    list lag {
        key "lag-name vrf";
        leaf lag-name { type string; }
        leaf vrf { type string; }
        leaf profile { type string; }
        leaf detection-multiplier { type uint8; }
        leaf desired-transmission-interval { type uint32; }
        leaf required-receive-interval { type uint32; }
        leaf administrative-down { type boolean; }

        list member-link {
            key "name";
            leaf name { type string; }
            leaf local-address { type inet:ip-address; }
            leaf peer-address { type inet:ip-address; }
            // ... timer overrides ...

            container stats {
                leaf link-up { type boolean; }
                leaf bfd-up { type boolean; }
                // ... session info ...
            }
        }

        container stats {
            leaf total-members { type uint8; }
            leaf active-members { type uint8; }
        }
    }

CLI Implementation
------------------

Two CLI nodes are defined:

- ``BFD_LAG_NODE`` - LAG configuration (``config-bfd-lag``)
- ``BFD_LAG_MEMBER_NODE`` - Member configuration (``config-bfd-lag-member``)

Commands are implemented in ``bfdd/bfdd_cli.c``.

Northbound Callbacks
--------------------

Configuration callbacks are in ``bfdd/bfdd_nb_config.c``:

- ``bfdd_bfd_lag_create()`` / ``bfdd_bfd_lag_destroy()``
- ``bfdd_bfd_lag_member_link_create()`` / ``bfdd_bfd_lag_member_link_destroy()``

State callbacks are in ``bfdd/bfdd_nb_state.c``:

- ``bfdd_bfd_lag_stats_*_get_elem()``
- ``bfdd_bfd_lag_member_link_stats_*_get_elem()``

Testing
-------

Unit tests are in ``tests/bfdd/test_bfd_lag.py``.

Topotests are in ``tests/topotests/bfd_lag_*/``.

References
----------

- :rfc:`7130` - Bidirectional Forwarding Detection (BFD) on Link Aggregation Group (LAG) Interfaces
- :rfc:`5880` - Bidirectional Forwarding Detection (BFD)
