#include <stdlib.h>
#include <string.h>

#include "packet_queue.h"

void rawpacket_queue_init(struct rawpacket_tailhead *q)
{
	TAILQ_INIT(q);
}
void rawpacket_free(struct rawpacket *rp)
{
	if (rp)
		free(rp->packet);
	free(rp);
}
struct rawpacket *rawpacket_dequeue(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	rp = TAILQ_FIRST(q);
	if (rp)
		TAILQ_REMOVE(q, rp, next);
	return rp;
}
void rawpacket_queue_destroy(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	while ((rp = rawpacket_dequeue(q)))
		rawpacket_free(rp);
}

struct rawpacket *rawpacket_queue(struct rawpacket_tailhead *q, const struct sockaddr_storage *dst, uint32_t fwmark, const char *ifout, const void *data, size_t len, size_t len_payload)
{
	struct rawpacket *rp = malloc(sizeof(struct rawpacket));
	if (!rp)
		return NULL;

	rp->packet = malloc(len);
	if (!rp->packet)
	{
		free(rp);
		return NULL;
	}

	rp->dst = *dst;
	rp->fwmark = fwmark;
	if (ifout)
	{
		strncpy(rp->ifout, ifout, sizeof(rp->ifout));
		rp->ifout[sizeof(rp->ifout) - 1] = 0;
	}
	else
		rp->ifout[0] = 0;
	memcpy(rp->packet, data, len);
	rp->len = len;
	rp->len_payload = len_payload;

	TAILQ_INSERT_TAIL(q, rp, next);

	return rp;
}

unsigned int rawpacket_queue_count(const struct rawpacket_tailhead *q)
{
	const struct rawpacket *rp;
	unsigned int ct = 0;
	TAILQ_FOREACH(rp, q, next)
	ct++;
	return ct;
}
bool rawpacket_queue_empty(const struct rawpacket_tailhead *q)
{
	return !TAILQ_FIRST(q);
}
