#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "packet_queue.h"

void rawpacket_queue_init(struct rawpacket_tailhead *q)
{
	TAILQ_INIT(&q->head);
	q->cached_count = 0;
}
void rawpacket_free(struct rawpacket *rp)
{
	if (rp) free(rp->packet);
	free(rp);
}
struct rawpacket *rawpacket_dequeue(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	rp = TAILQ_FIRST(&q->head);
	if (rp)
	{
		TAILQ_REMOVE(&q->head, rp, next);
		q->cached_count--;
	}
	return rp;
}
void rawpacket_queue_destroy(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	while((rp = rawpacket_dequeue(q))) rawpacket_free(rp);
}

struct rawpacket *rawpacket_queue(struct rawpacket_tailhead *q,const struct sockaddr_storage* dst,uint32_t fwmark,const char *ifin,const char *ifout,const void *data,size_t len,size_t len_payload)
{
	struct rawpacket *rp = malloc(sizeof(struct rawpacket));
	if (!rp) return NULL;

	rp->packet = malloc(len);
	if (!rp->packet)
	{
		free(rp);
		return NULL;
	}
	
	rp->dst = *dst;
	rp->fwmark = fwmark;
	if (ifin)
		snprintf(rp->ifin,sizeof(rp->ifin),"%s",ifin);
	else
		*rp->ifin = 0;
	if (ifout)
		snprintf(rp->ifout,sizeof(rp->ifout),"%s",ifout);
	else
		*rp->ifout = 0;
	memcpy(rp->packet,data,len);
	rp->len=len;
	rp->len_payload=len_payload;
	
	TAILQ_INSERT_TAIL(&q->head, rp, next);
	q->cached_count++;
	
	return rp;
}

unsigned int rawpacket_queue_count(const struct rawpacket_tailhead *q)
{
	return q->cached_count;
}
bool rawpacket_queue_empty(const struct rawpacket_tailhead *q)
{
	return !TAILQ_FIRST(&q->head);
}
