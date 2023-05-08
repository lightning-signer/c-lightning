/* common/jsonrpc_errors.h
 * Lists error codes for JSON-RPC.
 */
#ifndef LIGHTNING_COMMON_JSONRPC_ERRORS_H
#define LIGHTNING_COMMON_JSONRPC_ERRORS_H

#include "config.h"

#include <common/errcode.h>

enum jsonrpc_errcode {
	/* Standard errors defined by JSON-RPC 2.0 standard */
	JSONRPC2_INVALID_REQUEST = -32600,
	JSONRPC2_METHOD_NOT_FOUND = -32601,
	JSONRPC2_INVALID_PARAMS = -32602,

	/* Uncategorized error.
	 * FIXME: This should be replaced in all places
	 * with a specific error code, and then removed.
	 */
	LIGHTNINGD = -1,

	/* Developer error in the parameters to param() call */
	PARAM_DEV_ERROR = -2,

	/* Plugin returned an error */
	PLUGIN_ERROR = -3,

	/* Plugin terminated while handling a request. */
	PLUGIN_TERMINATED = -4,

	/* Lightningd is shutting down while handling a request. */
	LIGHTNINGD_SHUTDOWN = -5,

	/* Errors from `pay`, `sendpay`, or `waitsendpay` commands */
	PAY_IN_PROGRESS = 200,
	PAY_RHASH_ALREADY_USED = 201,
	PAY_UNPARSEABLE_ONION = 202,
	PAY_DESTINATION_PERM_FAIL = 203,
	PAY_TRY_OTHER_ROUTE = 204,
	PAY_ROUTE_NOT_FOUND = 205,
	PAY_ROUTE_TOO_EXPENSIVE = 206,
	PAY_INVOICE_EXPIRED = 207,
	PAY_NO_SUCH_PAYMENT = 208,
	PAY_UNSPECIFIED_ERROR = 209,
	PAY_STOPPED_RETRYING = 210,
	PAY_STATUS_UNEXPECTED = 211,
	PAY_INVOICE_REQUEST_INVALID = 212,

	/* `fundchannel` or `withdraw` errors */
	FUND_MAX_EXCEEDED = 300,
	FUND_CANNOT_AFFORD = 301,
	FUND_OUTPUT_IS_DUST = 302,
	FUNDING_BROADCAST_FAIL = 303,
	FUNDING_STILL_SYNCING_BITCOIN = 304,
	FUNDING_PEER_NOT_CONNECTED = 305,
	FUNDING_UNKNOWN_PEER = 306,
	FUNDING_NOTHING_TO_CANCEL = 307,
	FUNDING_CANCEL_NOT_SAFE = 308,
	FUNDING_PSBT_INVALID = 309,
	FUNDING_V2_NOT_SUPPORTED = 310,
	FUNDING_UNKNOWN_CHANNEL = 311,
	FUNDING_STATE_INVALID = 312,

	/* `connect` errors */
	CONNECT_NO_KNOWN_ADDRESS = 400,
	CONNECT_ALL_ADDRESSES_FAILED = 401,
	CONNECT_DISCONNECTED_DURING = 402,

	/* bitcoin-cli plugin errors */
	BCLI_ERROR = 500,

	/* Errors from `invoice` or `delinvoice` commands */
	INVOICE_LABEL_ALREADY_EXISTS = 900,
	INVOICE_PREIMAGE_ALREADY_EXISTS = 901,
	INVOICE_HINTS_GAVE_NO_ROUTES = 902,
	INVOICE_EXPIRED_DURING_WAIT = 903,
	INVOICE_WAIT_TIMED_OUT = 904,
	INVOICE_NOT_FOUND = 905,
	INVOICE_STATUS_UNEXPECTED = 906,
	INVOICE_OFFER_INACTIVE = 907,
	INVOICE_NO_DESCRIPTION = 908,

	/* Errors from HSM crypto operations. */
	HSM_ECDH_FAILED = 800,

	/* Errors from `offer` commands */
	OFFER_ALREADY_EXISTS = 1000,
	OFFER_ALREADY_DISABLED = 1001,
	OFFER_EXPIRED = 1002,
	OFFER_ROUTE_NOT_FOUND = 1003,
	OFFER_BAD_INVREQ_REPLY = 1004,
	OFFER_TIMEOUT = 1005,

	/* Errors from datastore command */
	DATASTORE_DEL_DOES_NOT_EXIST = 1200,
	DATASTORE_DEL_WRONG_GENERATION = 1201,
	DATASTORE_UPDATE_ALREADY_EXISTS = 1202,
	DATASTORE_UPDATE_DOES_NOT_EXIST = 1203,
	DATASTORE_UPDATE_WRONG_GENERATION = 1204,
	DATASTORE_UPDATE_HAS_CHILDREN = 1205,
	DATASTORE_UPDATE_NO_CHILDREN = 1206,

	/* Errors from signmessage command */
	SIGNMESSAGE_PUBKEY_NOT_FOUND = 1301,

	/* Errors from delforward command */
	DELFORWARD_NOT_FOUND = 1401,

	/* Errors from wait* commands */
	WAIT_TIMEOUT = 2000,
};

#endif /* LIGHTNING_COMMON_JSONRPC_ERRORS_H */
