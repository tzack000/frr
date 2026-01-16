// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD over LAG (Micro-BFD) - RFC 7130
 * Copyright (C) 2024 FRRouting
 */

#include <zebra.h>

#include "lib/json.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/vrf.h"
#include "lib/vty.h"
#include "lib/zclient.h"

#include "bfd.h"
#include "bfd_lag.h"

/*
 * Memory types
 */
DEFINE_MTYPE_STATIC(BFDD, BFD_LAG, "BFD LAG");
DEFINE_MTYPE_STATIC(BFDD, BFD_LAG_MEMBER, "BFD LAG Member");

/*
 * QOBJ types for VTY context
 */
DEFINE_QOBJ_TYPE(bfd_lag);
DEFINE_QOBJ_TYPE(bfd_lag_member);

/*
 * Global LAG list
 */
struct bfd_lag_list bfd_lag_list;

/*
 * Forward declarations
 */
static void bfd_lag_member_list_delete(void *data);
static struct bfd_session *bfd_lag_create_session(struct bfd_lag_member *member);

/*
 * Initialization and cleanup
 */
void bfd_lag_init(void)
{
	TAILQ_INIT(&bfd_lag_list);
}

void bfd_lag_finish(void)
{
	struct bfd_lag *lag;

	while (!TAILQ_EMPTY(&bfd_lag_list)) {
		lag = TAILQ_FIRST(&bfd_lag_list);
		bfd_lag_free(lag);
	}
}

/*
 * LAG Management Functions
 */
struct bfd_lag *bfd_lag_new(const char *lag_name, const char *vrfname)
{
	struct bfd_lag *lag;

	/* Check if LAG already exists */
	lag = bfd_lag_find(lag_name, vrfname);
	if (lag != NULL)
		return NULL;

	/* Allocate and initialize new LAG */
	lag = XCALLOC(MTYPE_BFD_LAG, sizeof(*lag));

	strlcpy(lag->lag_name, lag_name, sizeof(lag->lag_name));
	if (vrfname)
		strlcpy(lag->vrfname, vrfname, sizeof(lag->vrfname));
	else
		strlcpy(lag->vrfname, VRF_DEFAULT_NAME, sizeof(lag->vrfname));

	/* Initialize with default BFD timers */
	lag->detect_mult = BFD_DEFDETECTMULT;
	lag->min_tx = BFD_DEFDESIREDMINTX;
	lag->min_rx = BFD_DEFREQUIREDMINRX;
	lag->admin_shutdown = false;

	/* Create member list */
	lag->member_sessions = list_new();
	lag->member_sessions->del = bfd_lag_member_list_delete;

	/* Try to find the interface */
	lag->lag_ifp = if_lookup_by_name(lag_name, VRF_UNKNOWN);

	/* Add to global list */
	TAILQ_INSERT_TAIL(&bfd_lag_list, lag, entry);

	/* Register QOBJ for VTY context */
	QOBJ_REG(lag, bfd_lag);

	if (bglobal.debug_peer_event)
		zlog_debug("lag-new: created LAG %s (VRF %s)", lag_name,
			   lag->vrfname);

	return lag;
}

struct bfd_lag *bfd_lag_find(const char *lag_name, const char *vrfname)
{
	struct bfd_lag *lag;
	const char *vrf = vrfname ? vrfname : VRF_DEFAULT_NAME;

	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		if (strcmp(lag->lag_name, lag_name) == 0 &&
		    strcmp(lag->vrfname, vrf) == 0)
			return lag;
	}

	return NULL;
}

struct bfd_lag *bfd_lag_get(const char *lag_name, const char *vrfname)
{
	struct bfd_lag *lag;

	lag = bfd_lag_find(lag_name, vrfname);
	if (lag != NULL)
		return lag;

	return bfd_lag_new(lag_name, vrfname);
}

void bfd_lag_free(struct bfd_lag *lag)
{
	if (lag == NULL)
		return;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-free: deleting LAG %s", lag->lag_name);

	/* Unregister QOBJ */
	QOBJ_UNREG(lag);

	/* Remove from global list */
	TAILQ_REMOVE(&bfd_lag_list, lag, entry);

	/* Free member list (this will call bfd_lag_member_list_delete) */
	if (lag->member_sessions)
		list_delete(&lag->member_sessions);

	/* Free profile name if allocated */
	XFREE(MTYPE_BFD_LAG, lag->profile_name);

	/* Free LAG structure */
	XFREE(MTYPE_BFD_LAG, lag);
}

void bfd_lag_apply(struct bfd_lag *lag)
{
	struct listnode *node;
	struct bfd_lag_member *member;

	if (lag == NULL)
		return;

	/* Apply configuration to all members */
	for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
		if (member->bs != NULL) {
			uint64_t min_tx, min_rx;
			uint8_t detect_mult;

			bfd_lag_member_get_timers(member, &min_tx, &min_rx,
						  &detect_mult);

			/* Update session timers */
			member->bs->timers.desired_min_tx = min_tx;
			member->bs->timers.required_min_rx = min_rx;
			member->bs->detect_mult = detect_mult;

			/* Apply changes */
			bfd_set_polling(member->bs);
		}
	}
}

/*
 * LAG Member Management Functions
 */
static void bfd_lag_member_list_delete(void *data)
{
	struct bfd_lag_member *member = data;

	bfd_lag_member_free(member);
}

struct bfd_lag_member *bfd_lag_member_new(struct bfd_lag *lag,
					  const char *member_name)
{
	struct bfd_lag_member *member;

	if (lag == NULL || member_name == NULL)
		return NULL;

	/* Check if member already exists */
	member = bfd_lag_member_find(lag, member_name);
	if (member != NULL)
		return NULL;

	/* Allocate and initialize new member */
	member = XCALLOC(MTYPE_BFD_LAG_MEMBER, sizeof(*member));

	strlcpy(member->member_name, member_name, sizeof(member->member_name));
	member->lag = lag;

	/* Initialize addresses to unset */
	memset(&member->local_addr, 0, sizeof(member->local_addr));
	memset(&member->peer_addr, 0, sizeof(member->peer_addr));

	/* Timer overrides default to 0 (inherit from LAG) */
	member->min_tx = 0;
	member->min_rx = 0;
	member->detect_mult = 0;

	/* Status */
	member->link_up = false;
	member->bfd_up = false;
	member->protodown_set = false;

	/* Try to find the interface */
	member->member_ifp = if_lookup_by_name(member_name, VRF_UNKNOWN);
	if (member->member_ifp != NULL)
		member->link_up = if_is_up(member->member_ifp);

	/* Add to LAG's member list */
	listnode_add(lag->member_sessions, member);
	lag->total_members++;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-member-new: added member %s to LAG %s",
			   member_name, lag->lag_name);

	/* Register QOBJ for VTY context */
	QOBJ_REG(member, bfd_lag_member);

	return member;
}

struct bfd_lag_member *bfd_lag_member_find(struct bfd_lag *lag,
					   const char *member_name)
{
	struct listnode *node;
	struct bfd_lag_member *member;

	if (lag == NULL || member_name == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
		if (strcmp(member->member_name, member_name) == 0)
			return member;
	}

	return NULL;
}

struct bfd_lag_member *bfd_lag_member_get(struct bfd_lag *lag,
					  const char *member_name)
{
	struct bfd_lag_member *member;

	member = bfd_lag_member_find(lag, member_name);
	if (member != NULL)
		return member;

	return bfd_lag_member_new(lag, member_name);
}

void bfd_lag_member_free(struct bfd_lag_member *member)
{
	struct bfd_lag *lag;

	if (member == NULL)
		return;

	lag = member->lag;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-member-free: removing member %s from LAG %s",
			   member->member_name,
			   lag ? lag->lag_name : "unknown");

	/* Unregister QOBJ */
	QOBJ_UNREG(member);

	/* Disable BFD session if active */
	bfd_lag_member_disable(member);

	/* Remove from parent LAG's member list */
	if (lag != NULL) {
		listnode_delete(lag->member_sessions, member);
		lag->total_members--;
		if (member->bfd_up && lag->active_members > 0)
			lag->active_members--;
	}

	/* Free member structure */
	XFREE(MTYPE_BFD_LAG_MEMBER, member);
}

void bfd_lag_member_get_timers(const struct bfd_lag_member *member,
			       uint64_t *min_tx, uint64_t *min_rx,
			       uint8_t *detect_mult)
{
	struct bfd_lag *lag;
	struct bfd_profile *profile = NULL;

	if (member == NULL || member->lag == NULL)
		return;

	lag = member->lag;

	/* Check for profile */
	if (lag->profile_name)
		profile = bfd_profile_lookup(lag->profile_name);

	/* Calculate effective min_tx */
	if (member->min_tx > 0)
		*min_tx = member->min_tx;
	else if (lag->min_tx > 0)
		*min_tx = lag->min_tx;
	else if (profile && profile->min_tx > 0)
		*min_tx = profile->min_tx;
	else
		*min_tx = BFD_DEFDESIREDMINTX;

	/* Calculate effective min_rx */
	if (member->min_rx > 0)
		*min_rx = member->min_rx;
	else if (lag->min_rx > 0)
		*min_rx = lag->min_rx;
	else if (profile && profile->min_rx > 0)
		*min_rx = profile->min_rx;
	else
		*min_rx = BFD_DEFREQUIREDMINRX;

	/* Calculate effective detect_mult */
	if (member->detect_mult > 0)
		*detect_mult = member->detect_mult;
	else if (lag->detect_mult > 0)
		*detect_mult = lag->detect_mult;
	else if (profile && profile->detection_multiplier > 0)
		*detect_mult = profile->detection_multiplier;
	else
		*detect_mult = BFD_DEFDETECTMULT;
}

static struct bfd_session *bfd_lag_create_session(struct bfd_lag_member *member)
{
	struct bfd_peer_cfg bpc;
	struct bfd_session *bs;

	if (member == NULL || member->lag == NULL)
		return NULL;

	/* Verify addresses are configured */
	if (member->local_addr.sa_sin.sin_family == AF_UNSPEC ||
	    member->peer_addr.sa_sin.sin_family == AF_UNSPEC) {
		if (bglobal.debug_peer_event)
			zlog_debug("lag-session: member %s missing address config",
				   member->member_name);
		return NULL;
	}

	/* Verify interface exists */
	if (member->member_ifp == NULL) {
		if (bglobal.debug_peer_event)
			zlog_debug("lag-session: member %s interface not found",
				   member->member_name);
		return NULL;
	}

	/* Build peer configuration */
	memset(&bpc, 0, sizeof(bpc));

	/* Set addresses */
	bpc.bpc_peer = member->peer_addr;
	bpc.bpc_local = member->local_addr;
	bpc.bpc_ipv4 = (member->peer_addr.sa_sin.sin_family == AF_INET);

	/* Set interface */
	bpc.bpc_has_localif = true;
	strlcpy(bpc.bpc_localif, member->member_name, sizeof(bpc.bpc_localif));

	/* Set VRF */
	bpc.bpc_has_vrfname = true;
	strlcpy(bpc.bpc_vrfname, member->lag->vrfname, sizeof(bpc.bpc_vrfname));

	/* This is a single-hop session */
	bpc.bpc_mhop = false;

	/* Get effective timers */
	bfd_lag_member_get_timers(member, &bpc.bpc_txinterval,
				  &bpc.bpc_recvinterval,
				  &bpc.bpc_detectmultiplier);
	bpc.bpc_has_txinterval = true;
	bpc.bpc_has_recvinterval = true;
	bpc.bpc_has_detectmultiplier = true;

	/* Create BFD session */
	bs = ptm_bfd_sess_new(&bpc);
	if (bs == NULL) {
		zlog_warn("lag-session: failed to create BFD session for member %s",
			  member->member_name);
		return NULL;
	}

	/* Mark this as a Micro-BFD session */
	SET_FLAG(bs->flags, BFD_SESS_FLAG_MICRO_BFD);

	/* Store back-references (bidirectional) */
	member->bs = bs;
	bs->lag_member = member;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-session: created BFD session for member %s",
			   member->member_name);

	return bs;
}

int bfd_lag_member_enable(struct bfd_lag_member *member)
{
	struct bfd_session *bs;

	if (member == NULL)
		return -1;

	/* Already enabled? */
	if (member->bs != NULL)
		return 0;

	/* Check if LAG is administratively shutdown */
	if (member->lag && member->lag->admin_shutdown)
		return -1;

	/* Create the BFD session */
	bs = bfd_lag_create_session(member);
	if (bs == NULL)
		return -1;

	/* Enable the session */
	if (bfd_session_enable(bs) != 0) {
		bfd_session_free(bs);
		member->bs = NULL;
		return -1;
	}

	return 0;
}

void bfd_lag_member_disable(struct bfd_lag_member *member)
{
	if (member == NULL || member->bs == NULL)
		return;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-member-disable: disabling member %s",
			   member->member_name);

	/* Update state before freeing */
	if (member->bfd_up) {
		member->bfd_up = false;
		if (member->lag && member->lag->active_members > 0)
			member->lag->active_members--;
	}

	/* Clear protodown if it was set */
	if (member->protodown_set) {
		bfd_lag_notify_zebra(member, true);
		member->protodown_set = false;
	}

	/* Disable and free the BFD session */
	bfd_session_disable(member->bs);
	bfd_session_free(member->bs);
	member->bs = NULL;
}

/*
 * State Change Handlers
 */
void bfd_lag_session_state_change(struct bfd_lag_member *member, int new_state)
{
	bool was_up;
	bool is_up;

	if (member == NULL || member->lag == NULL)
		return;

	was_up = member->bfd_up;
	is_up = (new_state == PTM_BFD_UP);

	if (bglobal.debug_peer_event)
		zlog_debug("lag-state-change: member %s on LAG %s: %s -> %s",
			   member->member_name, member->lag->lag_name,
			   was_up ? "up" : "down",
			   is_up ? "up" : "down");

	/* Update member state */
	member->bfd_up = is_up;

	/* Update LAG active member count */
	if (is_up && !was_up) {
		member->lag->active_members++;
	} else if (!is_up && was_up) {
		if (member->lag->active_members > 0)
			member->lag->active_members--;
	}

	/* Notify zebra about state change for protodown handling */
	if (is_up != was_up) {
		bfd_lag_notify_zebra(member, is_up);
		member->protodown_set = !is_up;
	}
}

int bfd_lag_notify_zebra(struct bfd_lag_member *member, bool bfd_up)
{
	/*
	 * This function sends the ZEBRA_BFD_LAG_MEMBER_STATUS message
	 * to zebra, which will then set/clear protodown on the member
	 * interface.
	 */
	if (member == NULL || member->lag == NULL)
		return -1;

	if (bglobal.debug_zebra)
		zlog_debug("lag-notify-zebra: member %s on LAG %s, bfd_up=%d",
			   member->member_name, member->lag->lag_name, bfd_up);

	/* Send the zclient message */
	return ptm_bfd_notify_lag_member(member, bfd_up);
}

/*
 * Interface Event Handlers
 */
void bfd_lag_interface_add(struct interface *ifp)
{
	struct bfd_lag *lag;
	struct listnode *node;
	struct bfd_lag_member *member;

	if (ifp == NULL)
		return;

	/* Check if this is a LAG interface */
	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		if (strcmp(lag->lag_name, ifp->name) == 0) {
			lag->lag_ifp = ifp;
			if (bglobal.debug_zebra)
				zlog_debug("lag-if-add: found LAG interface %s",
					   ifp->name);
		}

		/* Check if this is a member interface */
		for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
			if (strcmp(member->member_name, ifp->name) == 0) {
				member->member_ifp = ifp;
				member->link_up = if_is_up(ifp);

				if (bglobal.debug_zebra)
					zlog_debug("lag-if-add: found member %s",
						   ifp->name);

				/* Try to enable the session if not already */
				if (member->bs == NULL)
					bfd_lag_member_enable(member);
			}
		}
	}
}

void bfd_lag_interface_del(struct interface *ifp)
{
	struct bfd_lag *lag;
	struct listnode *node;
	struct bfd_lag_member *member;

	if (ifp == NULL)
		return;

	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		if (lag->lag_ifp == ifp) {
			lag->lag_ifp = NULL;
			if (bglobal.debug_zebra)
				zlog_debug("lag-if-del: lost LAG interface %s",
					   ifp->name);
		}

		for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
			if (member->member_ifp == ifp) {
				if (bglobal.debug_zebra)
					zlog_debug("lag-if-del: lost member %s",
						   ifp->name);

				/* Disable the session */
				bfd_lag_member_disable(member);
				member->member_ifp = NULL;
				member->link_up = false;
			}
		}
	}
}

/*
 * Profile Support
 */
void bfd_lag_profile_apply(struct bfd_lag *lag, const char *profile_name)
{
	if (lag == NULL)
		return;

	/* Free old profile name */
	XFREE(MTYPE_BFD_LAG, lag->profile_name);

	/* Set new profile name */
	if (profile_name)
		lag->profile_name = XSTRDUP(MTYPE_BFD_LAG, profile_name);

	/* Look up the profile */
	lag->profile = bfd_profile_lookup(profile_name);

	/* Apply to all members */
	bfd_lag_apply(lag);
}

void bfd_lag_profile_remove(struct bfd_lag *lag)
{
	if (lag == NULL)
		return;

	XFREE(MTYPE_BFD_LAG, lag->profile_name);
	lag->profile = NULL;

	/* Re-apply with default values */
	bfd_lag_apply(lag);
}

/*
 * Iteration Functions
 */
void bfd_lag_iterate(bfd_lag_iter_func func, void *arg)
{
	struct bfd_lag *lag;

	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		func(lag, arg);
	}
}

unsigned long bfd_lag_get_count(void)
{
	struct bfd_lag *lag;
	unsigned long count = 0;

	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		count++;
	}

	return count;
}

/*
 * Display Functions
 */
static const char *bfd_lag_state_str(struct bfd_lag_member *member)
{
	if (member->bs == NULL)
		return "disabled";

	switch (member->bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		return "admin-down";
	case PTM_BFD_DOWN:
		return "down";
	case PTM_BFD_INIT:
		return "init";
	case PTM_BFD_UP:
		return "up";
	default:
		return "unknown";
	}
}

void bfd_lag_show(struct vty *vty, const char *lag_name,
		  struct json_object *json)
{
	struct bfd_lag *lag;
	struct json_object *json_lag, *json_array = NULL;

	if (json)
		json_array = json_object_new_array();

	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		if (lag_name && strcmp(lag->lag_name, lag_name) != 0)
			continue;

		if (json) {
			json_lag = json_object_new_object();
			json_object_string_add(json_lag, "lagName",
					       lag->lag_name);
			json_object_string_add(json_lag, "vrfName",
					       lag->vrfname);
			json_object_int_add(json_lag, "totalMembers",
					    lag->total_members);
			json_object_int_add(json_lag, "activeMembers",
					    lag->active_members);
			json_object_int_add(json_lag, "minTxInterval",
					    lag->min_tx);
			json_object_int_add(json_lag, "minRxInterval",
					    lag->min_rx);
			json_object_int_add(json_lag, "detectMultiplier",
					    lag->detect_mult);
			json_object_boolean_add(json_lag, "adminShutdown",
						lag->admin_shutdown);
			if (lag->profile_name)
				json_object_string_add(json_lag, "profile",
						       lag->profile_name);

			json_object_array_add(json_array, json_lag);
		} else {
			vty_out(vty, "LAG %s (VRF %s)\n", lag->lag_name,
				lag->vrfname);
			vty_out(vty, "  Members: %u active / %u total\n",
				lag->active_members, lag->total_members);
			vty_out(vty, "  Timers: tx=%u rx=%u multiplier=%u\n",
				lag->min_tx / 1000, lag->min_rx / 1000,
				lag->detect_mult);
			if (lag->profile_name)
				vty_out(vty, "  Profile: %s\n",
					lag->profile_name);
			if (lag->admin_shutdown)
				vty_out(vty, "  Status: administratively shutdown\n");
			vty_out(vty, "\n");
		}
	}

	if (json)
		json_object_object_add(json, "lags", json_array);
}

void bfd_lag_show_members(struct vty *vty, struct bfd_lag *lag,
			  struct json_object *json)
{
	struct listnode *node;
	struct bfd_lag_member *member;
	struct json_object *json_member, *json_array = NULL;

	if (lag == NULL)
		return;

	if (json)
		json_array = json_object_new_array();

	for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
		if (json) {
			json_member = json_object_new_object();
			json_object_string_add(json_member, "memberName",
					       member->member_name);
			json_object_string_add(json_member, "localAddress",
					       satostr(&member->local_addr));
			json_object_string_add(json_member, "peerAddress",
					       satostr(&member->peer_addr));
			json_object_string_add(json_member, "state",
					       bfd_lag_state_str(member));
			json_object_boolean_add(json_member, "linkUp",
						member->link_up);
			json_object_boolean_add(json_member, "bfdUp",
						member->bfd_up);
			json_object_boolean_add(json_member, "protodownSet",
						member->protodown_set);

			if (member->bs) {
				json_object_int_add(json_member, "localDiscr",
						    member->bs->discrs.my_discr);
				json_object_int_add(json_member, "remoteDiscr",
						    member->bs->discrs.remote_discr);
			}

			json_object_array_add(json_array, json_member);
		} else {
			vty_out(vty, "  Member %s\n", member->member_name);
			vty_out(vty, "    Local address: %s\n",
				satostr(&member->local_addr));
			vty_out(vty, "    Peer address: %s\n",
				satostr(&member->peer_addr));
			vty_out(vty, "    BFD state: %s\n",
				bfd_lag_state_str(member));
			vty_out(vty, "    Link: %s, BFD: %s, Protodown: %s\n",
				member->link_up ? "up" : "down",
				member->bfd_up ? "up" : "down",
				member->protodown_set ? "set" : "clear");
			if (member->bs) {
				vty_out(vty, "    Discriminator: local=%u remote=%u\n",
					member->bs->discrs.my_discr,
					member->bs->discrs.remote_discr);
			}
			vty_out(vty, "\n");
		}
	}

	if (json)
		json_object_object_add(json, "members", json_array);
}

/*
 * Configuration Write
 */
int bfd_lag_config_write(struct vty *vty)
{
	struct bfd_lag *lag;
	struct listnode *node;
	struct bfd_lag_member *member;
	int lines = 0;

	TAILQ_FOREACH (lag, &bfd_lag_list, entry) {
		vty_out(vty, " lag %s\n", lag->lag_name);
		lines++;

		if (lag->profile_name) {
			vty_out(vty, "  profile %s\n", lag->profile_name);
			lines++;
		}

		if (lag->detect_mult != BFD_DEFDETECTMULT) {
			vty_out(vty, "  detect-multiplier %u\n",
				lag->detect_mult);
			lines++;
		}

		if (lag->min_tx != BFD_DEFDESIREDMINTX) {
			vty_out(vty, "  transmit-interval %u\n",
				lag->min_tx / 1000);
			lines++;
		}

		if (lag->min_rx != BFD_DEFREQUIREDMINRX) {
			vty_out(vty, "  receive-interval %u\n",
				lag->min_rx / 1000);
			lines++;
		}

		if (lag->admin_shutdown) {
			vty_out(vty, "  shutdown\n");
			lines++;
		}

		for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
			vty_out(vty, "  member-link %s\n", member->member_name);
			lines++;

			if (member->local_addr.sa_sin.sin_family != AF_UNSPEC) {
				vty_out(vty, "   local-address %s\n",
					satostr(&member->local_addr));
				lines++;
			}

			if (member->peer_addr.sa_sin.sin_family != AF_UNSPEC) {
				vty_out(vty, "   peer-address %s\n",
					satostr(&member->peer_addr));
				lines++;
			}

			if (member->detect_mult > 0) {
				vty_out(vty, "   detect-multiplier %u\n",
					member->detect_mult);
				lines++;
			}

			if (member->min_tx > 0) {
				vty_out(vty, "   transmit-interval %u\n",
					member->min_tx / 1000);
				lines++;
			}

			if (member->min_rx > 0) {
				vty_out(vty, "   receive-interval %u\n",
					member->min_rx / 1000);
				lines++;
			}

			vty_out(vty, "  exit\n");
			lines++;
		}

		vty_out(vty, " exit\n");
		lines++;
	}

	return lines;
}

/*
 * CLI Support Functions
 */
void bfd_lag_set_profile(struct bfd_lag *lag, const char *profile_name)
{
	if (lag == NULL)
		return;

	if (profile_name)
		bfd_lag_profile_apply(lag, profile_name);
	else
		bfd_lag_profile_remove(lag);
}

void bfd_lag_set_shutdown(struct bfd_lag *lag, bool shutdown)
{
	struct listnode *node;
	struct bfd_lag_member *member;

	if (lag == NULL)
		return;

	if (lag->admin_shutdown == shutdown)
		return;

	lag->admin_shutdown = shutdown;

	if (shutdown) {
		/* Disable all member sessions */
		for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
			bfd_lag_member_disable(member);
		}
	} else {
		/* Re-enable all member sessions */
		for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
			bfd_lag_member_enable(member);
		}
	}

	if (bglobal.debug_peer_event)
		zlog_debug("lag-shutdown: LAG %s %s", lag->lag_name,
			   shutdown ? "shutdown" : "enabled");
}

void bfd_lag_update_timers(struct bfd_lag *lag)
{
	struct listnode *node;
	struct bfd_lag_member *member;

	if (lag == NULL)
		return;

	/* Update timer values on all active sessions */
	for (ALL_LIST_ELEMENTS_RO(lag->member_sessions, node, member)) {
		if (member->bs != NULL) {
			uint64_t min_tx, min_rx;
			uint8_t detect_mult;

			bfd_lag_member_get_timers(member, &min_tx, &min_rx,
						  &detect_mult);

			/* Update session timers */
			member->bs->timers.desired_min_tx = min_tx;
			member->bs->timers.required_min_rx = min_rx;
			member->bs->detect_mult = detect_mult;

			/* Apply changes */
			bfd_set_polling(member->bs);
		}
	}
}

void bfd_lag_member_set_local_address(struct bfd_lag_member *member,
				      const struct sockaddr_any *addr)
{
	if (member == NULL || addr == NULL)
		return;

	member->local_addr = *addr;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-member-addr: member %s local %s",
			   member->member_name, satostr(addr));

	/* Re-enable session if both addresses are configured */
	if (member->peer_addr.sa_sin.sin_family != AF_UNSPEC &&
	    member->bs == NULL && member->lag && !member->lag->admin_shutdown) {
		bfd_lag_member_enable(member);
	}
}

void bfd_lag_member_set_peer_address(struct bfd_lag_member *member,
				     const struct sockaddr_any *addr)
{
	if (member == NULL || addr == NULL)
		return;

	member->peer_addr = *addr;

	if (bglobal.debug_peer_event)
		zlog_debug("lag-member-addr: member %s peer %s",
			   member->member_name, satostr(addr));

	/* Re-enable session if both addresses are configured */
	if (member->local_addr.sa_sin.sin_family != AF_UNSPEC &&
	    member->bs == NULL && member->lag && !member->lag->admin_shutdown) {
		bfd_lag_member_enable(member);
	}
}
