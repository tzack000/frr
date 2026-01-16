// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD over LAG (Micro-BFD) - RFC 7130
 * Copyright (C) 2024 FRRouting
 */

#ifndef _BFD_LAG_H_
#define _BFD_LAG_H_

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/queue.h"
#include "lib/sockopt.h"
#include "lib/qobj.h"

/* Forward declarations */
struct bfd_session;
struct bfd_profile;
struct vty;
struct json_object;

/*
 * Micro-BFD UDP port per RFC 7130
 */
#define BFD_DEF_MICRO_BFD_PORT 6784

/*
 * Micro-BFD LAG session group
 *
 * This structure represents a LAG interface with its Micro-BFD configuration.
 * Each LAG can have multiple member links, each running an independent BFD
 * session.
 */
struct bfd_lag {
	/* LAG interface name (e.g., bond0, PortChannel001) */
	char lag_name[IFNAMSIZ];

	/* LAG interface pointer (may be NULL if interface doesn't exist yet) */
	struct interface *lag_ifp;

	/* VRF name */
	char vrfname[VRF_NAMSIZ];

	/* Configuration parameters (applied to all members unless overridden) */
	uint8_t detect_mult;
	uint32_t min_tx;	/* microseconds */
	uint32_t min_rx;	/* microseconds */
	bool admin_shutdown;

	/* Profile support */
	char *profile_name;
	struct bfd_profile *profile;

	/* Member link sessions list */
	struct list *member_sessions;

	/* Status counters */
	uint8_t active_members;	  /* Members with BFD Up */
	uint8_t total_members;	  /* Total configured members */

	/* List entry for global LAG list */
	TAILQ_ENTRY(bfd_lag) entry;

	/* QOBJ for VTY context */
	QOBJ_FIELDS;
};

/* LAG list head type */
TAILQ_HEAD(bfd_lag_list, bfd_lag);
DECLARE_QOBJ_TYPE(bfd_lag);

/*
 * Micro-BFD LAG member session
 *
 * Represents a single member link within a LAG, running its own BFD session.
 */
struct bfd_lag_member {
	/* Member interface name (e.g., eth0, Ethernet0) */
	char member_name[IFNAMSIZ];

	/* Member interface pointer (may be NULL if interface doesn't exist) */
	struct interface *member_ifp;

	/* Parent LAG pointer */
	struct bfd_lag *lag;

	/* Address configuration */
	struct sockaddr_any local_addr;
	struct sockaddr_any peer_addr;

	/* Member-level timer overrides (0 means use LAG-level value) */
	uint32_t min_tx;	/* microseconds, 0 = inherit from LAG */
	uint32_t min_rx;	/* microseconds, 0 = inherit from LAG */
	uint8_t detect_mult;	/* 0 = inherit from LAG */

	/* BFD session associated with this member */
	struct bfd_session *bs;

	/* Status flags */
	bool link_up;		/* Physical link status */
	bool bfd_up;		/* BFD session status */
	bool protodown_set;	/* Whether protodown has been set on interface */

	/* List node for member list in parent LAG */
	struct listnode node;

	/* QOBJ for VTY context */
	QOBJ_FIELDS;
};

DECLARE_QOBJ_TYPE(bfd_lag_member);

/*
 * Global LAG list
 */
extern struct bfd_lag_list bfd_lag_list;

/*
 * LAG Management Functions
 */

/**
 * Initialize the Micro-BFD LAG subsystem.
 */
void bfd_lag_init(void);

/**
 * Shutdown the Micro-BFD LAG subsystem and free all resources.
 */
void bfd_lag_finish(void);

/**
 * Create a new LAG session group.
 *
 * @param lag_name LAG interface name
 * @param vrfname VRF name (NULL for default VRF)
 * @return Pointer to the new LAG structure, or NULL on failure
 */
struct bfd_lag *bfd_lag_new(const char *lag_name, const char *vrfname);

/**
 * Find an existing LAG session group by name.
 *
 * @param lag_name LAG interface name
 * @param vrfname VRF name (NULL for default VRF)
 * @return Pointer to the LAG structure, or NULL if not found
 */
struct bfd_lag *bfd_lag_find(const char *lag_name, const char *vrfname);

/**
 * Find or create a LAG session group.
 *
 * @param lag_name LAG interface name
 * @param vrfname VRF name (NULL for default VRF)
 * @return Pointer to the LAG structure (existing or newly created)
 */
struct bfd_lag *bfd_lag_get(const char *lag_name, const char *vrfname);

/**
 * Delete a LAG session group and all its members.
 *
 * @param lag Pointer to the LAG structure
 */
void bfd_lag_free(struct bfd_lag *lag);

/**
 * Apply configuration to a LAG session group.
 *
 * @param lag Pointer to the LAG structure
 */
void bfd_lag_apply(struct bfd_lag *lag);

/*
 * LAG Member Management Functions
 */

/**
 * Add a new member link to a LAG.
 *
 * @param lag Parent LAG structure
 * @param member_name Member interface name
 * @return Pointer to the new member structure, or NULL on failure
 */
struct bfd_lag_member *bfd_lag_member_new(struct bfd_lag *lag,
					  const char *member_name);

/**
 * Find a member link in a LAG by name.
 *
 * @param lag Parent LAG structure
 * @param member_name Member interface name
 * @return Pointer to the member structure, or NULL if not found
 */
struct bfd_lag_member *bfd_lag_member_find(struct bfd_lag *lag,
					   const char *member_name);

/**
 * Find or create a member link in a LAG.
 *
 * @param lag Parent LAG structure
 * @param member_name Member interface name
 * @return Pointer to the member structure (existing or newly created)
 */
struct bfd_lag_member *bfd_lag_member_get(struct bfd_lag *lag,
					  const char *member_name);

/**
 * Delete a member link from a LAG.
 *
 * @param member Pointer to the member structure
 */
void bfd_lag_member_free(struct bfd_lag_member *member);

/**
 * Enable the BFD session for a member link.
 *
 * @param member Pointer to the member structure
 * @return 0 on success, -1 on failure
 */
int bfd_lag_member_enable(struct bfd_lag_member *member);

/**
 * Disable the BFD session for a member link.
 *
 * @param member Pointer to the member structure
 */
void bfd_lag_member_disable(struct bfd_lag_member *member);

/**
 * Get the effective timer value for a member, considering inheritance.
 *
 * @param member Pointer to the member structure
 * @param min_tx Output: effective min_tx value
 * @param min_rx Output: effective min_rx value
 * @param detect_mult Output: effective detect_mult value
 */
void bfd_lag_member_get_timers(const struct bfd_lag_member *member,
			       uint64_t *min_tx, uint64_t *min_rx,
			       uint8_t *detect_mult);

/*
 * State Change Handlers
 */

/**
 * Called when a Micro-BFD session state changes.
 *
 * @param member Pointer to the member structure
 * @param new_state New BFD state (PTM_BFD_UP, PTM_BFD_DOWN, etc.)
 */
void bfd_lag_session_state_change(struct bfd_lag_member *member, int new_state);

/**
 * Notify zebra about a LAG member status change.
 *
 * @param member Pointer to the member structure
 * @param bfd_up Whether the BFD session is up
 * @return 0 on success, -1 on failure
 */
int bfd_lag_notify_zebra(struct bfd_lag_member *member, bool bfd_up);

/*
 * Interface Event Handlers
 */

/**
 * Handle interface addition event.
 *
 * @param ifp Interface pointer
 */
void bfd_lag_interface_add(struct interface *ifp);

/**
 * Handle interface deletion event.
 *
 * @param ifp Interface pointer
 */
void bfd_lag_interface_del(struct interface *ifp);

/*
 * Profile Support
 */

/**
 * Apply a BFD profile to a LAG.
 *
 * @param lag Pointer to the LAG structure
 * @param profile_name Profile name
 */
void bfd_lag_profile_apply(struct bfd_lag *lag, const char *profile_name);

/**
 * Remove the applied profile from a LAG.
 *
 * @param lag Pointer to the LAG structure
 */
void bfd_lag_profile_remove(struct bfd_lag *lag);

/**
 * Set or remove a profile on a LAG.
 *
 * @param lag Pointer to the LAG structure
 * @param profile_name Profile name (NULL to remove)
 */
void bfd_lag_set_profile(struct bfd_lag *lag, const char *profile_name);

/**
 * Administratively shutdown a LAG.
 *
 * @param lag Pointer to the LAG structure
 * @param shutdown true to shutdown, false to enable
 */
void bfd_lag_set_shutdown(struct bfd_lag *lag, bool shutdown);

/**
 * Update timers for all member sessions in a LAG.
 *
 * @param lag Pointer to the LAG structure
 */
void bfd_lag_update_timers(struct bfd_lag *lag);

/**
 * Set local address for a member.
 *
 * @param member Pointer to the member structure
 * @param addr Local address
 */
void bfd_lag_member_set_local_address(struct bfd_lag_member *member,
				      const struct sockaddr_any *addr);

/**
 * Set peer address for a member.
 *
 * @param member Pointer to the member structure
 * @param addr Peer address
 */
void bfd_lag_member_set_peer_address(struct bfd_lag_member *member,
				     const struct sockaddr_any *addr);

/*
 * Iteration Functions
 */

/**
 * Iterate over all LAG session groups.
 *
 * @param func Callback function
 * @param arg User argument passed to callback
 */
typedef void (*bfd_lag_iter_func)(struct bfd_lag *lag, void *arg);
void bfd_lag_iterate(bfd_lag_iter_func func, void *arg);

/**
 * Get the count of configured LAG session groups.
 *
 * @return Number of configured LAGs
 */
unsigned long bfd_lag_get_count(void);

/*
 * Display Functions
 */

/**
 * Show LAG session information.
 *
 * @param vty VTY output
 * @param lag_name Optional LAG name filter (NULL for all)
 * @param json JSON object for JSON output (NULL for text output)
 */
void bfd_lag_show(struct vty *vty, const char *lag_name,
		  struct json_object *json);

/**
 * Show LAG member session information.
 *
 * @param vty VTY output
 * @param lag LAG structure
 * @param json JSON object for JSON output (NULL for text output)
 */
void bfd_lag_show_members(struct vty *vty, struct bfd_lag *lag,
			  struct json_object *json);

/*
 * Configuration Write
 */

/**
 * Write LAG configuration to vty.
 *
 * @param vty VTY output
 * @return Number of lines written
 */
int bfd_lag_config_write(struct vty *vty);

#endif /* _BFD_LAG_H_ */
