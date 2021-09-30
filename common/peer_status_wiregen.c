/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the .csv file it was generated from. */
/* Original template can be found at tools/gen/impl_template */

#include <common/peer_status_wiregen.h>
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif


const char *peer_status_wire_name(int e)
{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	switch ((enum peer_status_wire)e) {
	case WIRE_STATUS_PEER_ERROR: return "WIRE_STATUS_PEER_ERROR";
	}

	snprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
	return invalidbuf;
}

bool peer_status_wire_is_defined(u16 type)
{
	switch ((enum peer_status_wire)type) {
	case WIRE_STATUS_PEER_ERROR:;
	      return true;
	}
	return false;
}





/* WIRE: STATUS_PEER_ERROR */
/* An error occurred: if error_for_them */
u8 *towire_status_peer_error(const tal_t *ctx, const struct channel_id *channel, const wirestring *desc, bool warning, const struct per_peer_state *pps, const u8 *error_for_them)
{
	u16 len = tal_count(error_for_them);
	u8 *p = tal_arr(ctx, u8, 0);

	towire_u16(&p, WIRE_STATUS_PEER_ERROR);
	/* This is implied if error_for_them */
	towire_channel_id(&p, channel);
	towire_wirestring(&p, desc);
	/* Take a deep breath */
	towire_bool(&p, warning);
	towire_per_peer_state(&p, pps);
	towire_u16(&p, len);
	towire_u8_array(&p, error_for_them, len);

	return memcheck(p, tal_count(p));
}
bool fromwire_status_peer_error(const tal_t *ctx, const void *p, struct channel_id *channel, wirestring **desc, bool *warning, struct per_peer_state **pps, u8 **error_for_them)
{
	u16 len;

	const u8 *cursor = p;
	size_t plen = tal_count(p);

	if (fromwire_u16(&cursor, &plen) != WIRE_STATUS_PEER_ERROR)
		return false;
 	/* This is implied if error_for_them */
	fromwire_channel_id(&cursor, &plen, channel);
 	*desc = fromwire_wirestring(ctx, &cursor, &plen);
 	/* Take a deep breath */
	*warning = fromwire_bool(&cursor, &plen);
 	*pps = fromwire_per_peer_state(ctx, &cursor, &plen);
 	len = fromwire_u16(&cursor, &plen);
 	// 2nd case error_for_them
	*error_for_them = len ? tal_arr(ctx, u8, len) : NULL;
	fromwire_u8_array(&cursor, &plen, *error_for_them, len);
	return cursor != NULL;
}
// SHA256STAMP:fa8231356935e5f2eb2d555bd52fa44e7c79be16d57aa158ae209cc9b10939e8
