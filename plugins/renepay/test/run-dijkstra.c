#include "config.h"
#include <stdio.h>
#include <assert.h>
#include <common/wireaddr.h>
#include <common/bigsize.h>
#include <common/channel_id.h>
#include <common/setup.h>
#include <common/utils.h>

#include <plugins/renepay/dijkstra.h>

static void insertion_in_increasing_distance(const tal_t *ctx)
{
	struct dijkstra *dijkstra = dijkstra_new(ctx,10);

	for(int i=0;i<dijkstra_maxsize(dijkstra);++i)
	{
		dijkstra_update(dijkstra,i,10+i);
		assert(dijkstra_size(dijkstra)==(i+1));
	}

	dijkstra_update(dijkstra,3,3);
	assert(dijkstra_top(dijkstra)==3);

	dijkstra_update(dijkstra,3,15);
	assert(dijkstra_top(dijkstra)==0);

	dijkstra_update(dijkstra,3,-1);
	assert(dijkstra_top(dijkstra)==3);

	dijkstra_pop(dijkstra);
	assert(dijkstra_size(dijkstra)==9);
	assert(dijkstra_top(dijkstra)==0);

	// Insert again
	dijkstra_update(dijkstra,3,3+10);

	u32 top=0;
	while(!dijkstra_empty(dijkstra))
	{
		assert(top==dijkstra_top(dijkstra));
		top++;
		dijkstra_pop(dijkstra);
	}
}
static void insertion_in_decreasing_distance(const tal_t *ctx)
{
	struct dijkstra *dijkstra = dijkstra_new(ctx,10);

	for(int i=0;i<dijkstra_maxsize(dijkstra);++i)
	{
		dijkstra_update(dijkstra,i,10-i);
		assert(dijkstra_size(dijkstra)==(i+1));
	}

	dijkstra_update(dijkstra,3,-3);
	assert(dijkstra_top(dijkstra)==3);

	dijkstra_update(dijkstra,3,15);
	assert(dijkstra_top(dijkstra)==9);

	dijkstra_update(dijkstra,3,-1);
	assert(dijkstra_top(dijkstra)==3);

	dijkstra_pop(dijkstra);
	assert(dijkstra_size(dijkstra)==9);
	assert(dijkstra_top(dijkstra)==9);

	// Insert again
	dijkstra_update(dijkstra,3,10-3);

	u32 top=9;
	while(!dijkstra_empty(dijkstra))
	{
		assert(top==dijkstra_top(dijkstra));
		top--;
		dijkstra_pop(dijkstra);
	}
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	// does tal_free() cleansup correctly?
	const tal_t *this_ctx = tal(NULL,tal_t);
	insertion_in_increasing_distance(this_ctx);
	tal_free(this_ctx);
	insertion_in_decreasing_distance(tmpctx);

	common_shutdown();
}
