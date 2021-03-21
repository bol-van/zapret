#include "conntrack.h"
#include "darkmagic.h"
#include <arpa/inet.h>
#include <stdio.h>

#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)

static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}


static const char *connstate_s[]={"SYN","ESTABLISHED","FIN"};

#define _connswap \
	memset(c2,0,sizeof(*c2)); \
	c2->e1 = c->e2; \
	c2->e2 = c->e1;

static void connswap4(const t_conn4 *c, t_conn4 *c2)
{
	_connswap
}
static void connswap6(const t_conn6 *c, t_conn6 *c2)
{
	_connswap
}


#define _ConntrackPoolDestroy(v) \
	t_conntrack##v *elem, *tmp; \
	HASH_ITER(hh, *pp, elem, tmp) { HASH_DEL(*pp, elem); free(elem); }
static void ConntrackPoolDestroy4(t_conntrack4 **pp)
{
	_ConntrackPoolDestroy(4)
}
static void ConntrackPoolDestroy6(t_conntrack6 **pp)
{
	_ConntrackPoolDestroy(6)
}
void ConntrackPoolDestroy(t_conntrack *p)
{
	ConntrackPoolDestroy4(&p->pool4);
	ConntrackPoolDestroy6(&p->pool6);
}

void ConntrackPoolInit(t_conntrack *p, time_t purge_interval, uint32_t timeout_syn, uint32_t timeout_established, uint32_t timeout_fin)
{
	p->timeout_syn = timeout_syn;
	p->timeout_established = timeout_established;
	p->timeout_fin = timeout_fin;
	p->t_purge_interval = purge_interval;
	time(&p->t_last_purge);
	p->pool4 = NULL;
	p->pool6 = NULL;
}


#define _ConntrackExtractConn(v) \
	memset(c,0,sizeof(*c)); \
	if (bReverse) { \
		c->e1.adr = ip->ip##v##_dst; \
		c->e2.adr = ip->ip##v##_src; \
		c->e1.port = htons(tcphdr->th_dport); \
		c->e2.port = htons(tcphdr->th_sport); \
	} else { \
		c->e1.adr = ip->ip##v##_src; \
		c->e2.adr = ip->ip##v##_dst; \
		c->e1.port = htons(tcphdr->th_sport); \
		c->e2.port = htons(tcphdr->th_dport); \
	}
void ConntrackExtractConn4(t_conn4 *c, bool bReverse, const struct ip *ip, const struct tcphdr *tcphdr)
{
	_ConntrackExtractConn()
}
void ConntrackExtractConn6(t_conn6 *c, bool bReverse, const struct ip6_hdr *ip, const struct tcphdr *tcphdr)
{
	_ConntrackExtractConn(6)
}

#define _ConntrackPoolSearch(v) \
	t_conntrack##v *t; \
	HASH_FIND(hh, p, c, sizeof(*c), t); \
	return t;
t_conntrack4 *ConntrackPoolSearch4(t_conntrack4 *p, const t_conn4 *c)
{
	_ConntrackPoolSearch(4)
}
t_conntrack6 *ConntrackPoolSearch6(t_conntrack6 *p, const t_conn6 *c)
{
	_ConntrackPoolSearch(6)
}


static void ConntrackInitTrack(t_ctrack *t)
{
	memset(t,0,sizeof(*t));
	t->scale_orig = t->scale_reply = SCALE_NONE;
	time(&t->t_start);
}

#define _ConntrackNew(v) \
	t_conntrack##v *new; \
	if (!(new = calloc(1,sizeof(*new)))) return NULL; \
	new->conn = *c; \
	oom = false; \
	HASH_ADD(hh, *pp, conn, sizeof(*c), new); \
	if (oom) { free(new); return NULL; } \
	ConntrackInitTrack(&new->track); \
	return new;
static t_conntrack4 *ConntrackNew4(t_conntrack4 **pp, const t_conn4 *c)
{
	_ConntrackNew(4)
}
static t_conntrack6 *ConntrackNew6(t_conntrack6 **pp, const t_conn6 *c)
{
	_ConntrackNew(6)
}


static void ConntrackFeedPacket(t_ctrack *t, bool bReverse, const struct tcphdr *tcphdr, uint32_t len_payload)
{
	uint8_t scale;
	if (tcp_syn_segment(tcphdr))
	{
		if (t->state!=SYN) ConntrackInitTrack(t); // erase current entry
		t->seq0 = htonl(tcphdr->th_seq);
	}
	else if (tcp_synack_segment(tcphdr))
	{
		if (t->state!=SYN) ConntrackInitTrack(t); // erase current entry
		if (!t->seq0) t->seq0 = htonl(tcphdr->th_ack)-1;
		t->ack0 = htonl(tcphdr->th_seq);
	}
	else if (tcphdr->th_flags & (TH_FIN|TH_RST))
	{
		t->state = FIN;
	}
	else
	{
		if (t->state==SYN) 
		{
			t->state=ESTABLISHED;
			if (!bReverse && !t->ack0) t->ack0 = htonl(tcphdr->th_ack)-1;
		}
	}
	scale = tcp_find_scale_factor(tcphdr);
	if (bReverse)
	{
		t->seq_last = htonl(tcphdr->th_ack);
		t->ack_last = htonl(tcphdr->th_seq) + len_payload;
		t->pcounter_reply++;
		t->winsize_reply = htons(tcphdr->th_win);
		if (scale!=SCALE_NONE) t->scale_reply = scale;
		
	}
	else
	{
		t->seq_last = htonl(tcphdr->th_seq) + len_payload;
		t->ack_last = htonl(tcphdr->th_ack);
		t->pcounter_orig++;
		t->winsize_orig = htons(tcphdr->th_win);
		if (scale!=SCALE_NONE) t->scale_orig = scale;
	}
	time(&t->t_last);
}

#define _ConntrackPoolFeed(v) \
	t_conn##v conn, connswap; \
	t_conntrack##v *ctr; \
	bool b_rev; \
	ConntrackExtractConn##v(&conn,false,ip,tcphdr); \
	if ((ctr=ConntrackPoolSearch##v(*pp,&conn))) \
	{ \
		ConntrackFeedPacket(&ctr->track, (b_rev=false), tcphdr, len_payload); \
		goto ok; \
	} \
	else \
	{ \
		connswap##v(&conn,&connswap); \
		if ((ctr=ConntrackPoolSearch##v(*pp,&connswap))) \
		{ \
			ConntrackFeedPacket(&ctr->track, (b_rev=true), tcphdr, len_payload); \
			goto ok; \
		} \
	} \
	b_rev = tcp_synack_segment(tcphdr); \
	if (tcp_syn_segment(tcphdr) || b_rev) \
	{ \
		if ((ctr=ConntrackNew##v(pp, b_rev ? &connswap : &conn))) \
		{ \
			ConntrackFeedPacket(&ctr->track, b_rev, tcphdr, len_payload); \
			goto ok; \
		} \
	} \
	return false; \
ok: \
	if (ctrack) *ctrack = &ctr->track; \
	if (bReverse) *bReverse = b_rev; \
	return true;

static bool ConntrackPoolFeed4(t_conntrack4 **pp, const struct ip *ip, const struct tcphdr *tcphdr, uint32_t len_payload, t_ctrack **ctrack, bool *bReverse)
{
	_ConntrackPoolFeed(4)
}
static bool ConntrackPoolFeed6(t_conntrack6 **pp, const struct ip6_hdr *ip, const struct tcphdr *tcphdr, uint32_t len_payload, t_ctrack **ctrack, bool *bReverse)
{
	_ConntrackPoolFeed(6)
}
bool ConntrackPoolFeed(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr, size_t len_payload, t_ctrack **ctrack, bool *bReverse)
{
	return ip ? ConntrackPoolFeed4(&p->pool4,ip,tcphdr,(uint32_t)len_payload,ctrack,bReverse) : ip6 ? ConntrackPoolFeed6(&p->pool6,ip6,tcphdr,(uint32_t)len_payload,ctrack,bReverse) : false;
}


#define _ConntrackPoolDrop(v) \
	t_conn##v conn, connswap; \
	t_conntrack##v *t; \
	ConntrackExtractConn##v(&conn,false,ip,tcphdr); \
	if (!(t=ConntrackPoolSearch##v(*pp,&conn))) \
	{ \
		connswap##v(&conn,&connswap); \
		t=ConntrackPoolSearch##v(*pp,&connswap); \
	} \
	if (!t) return false; \
	HASH_DEL(*pp, t); free(t); \
	return true;
static bool ConntrackPoolDrop4(t_conntrack4 **pp, const struct ip *ip, const struct tcphdr *tcphdr)
{
	_ConntrackPoolDrop(4)
}
static bool ConntrackPoolDrop6(t_conntrack6 **pp, const struct ip6_hdr *ip, const struct tcphdr *tcphdr)
{
	_ConntrackPoolDrop(6)
}
bool ConntrackPoolDrop(t_conntrack *p, const struct ip *ip, const struct ip6_hdr *ip6, const struct tcphdr *tcphdr)
{
	return ip ? ConntrackPoolDrop4(&p->pool4,ip,tcphdr) : ip6 ? ConntrackPoolDrop6(&p->pool6,ip6,tcphdr) : false;
}

#define _ConntrackPoolPurge(v, pp) \
	{ \
		t_conntrack##v *t, *tmp; \
		time_t tidle; \
		HASH_ITER(hh, *pp , t, tmp) { \
			tidle = tnow - t->track.t_last; \
			if (	t->track.b_cutoff || \
				t->track.state==SYN && tidle>=p->timeout_syn || \
				t->track.state==ESTABLISHED && tidle>=p->timeout_established || \
				t->track.state==FIN && tidle>=p->timeout_fin) \
			{ \
				HASH_DEL(*pp, t); free(t);  \
			} \
		} \
	}

void ConntrackPoolPurge(t_conntrack *p)
{
	time_t tnow = time(NULL); \
	if ((tnow - p->t_last_purge)>=p->t_purge_interval)
	{
		_ConntrackPoolPurge(4, &p->pool4);
		_ConntrackPoolPurge(6, &p->pool6);
		p->t_last_purge = tnow;
	}
}


#define _ConntrackPoolDump(v,f) \
	t_conntrack##v *t, *tmp; \
	char sa1[40],sa2[40]; \
	time_t tnow = time(NULL); \
	HASH_ITER(hh, p, t, tmp) { \
		*sa1=0; inet_ntop(AF_INET##f, &t->conn.e1.adr, sa1, sizeof(sa1)); \
		*sa2=0; inet_ntop(AF_INET##f, &t->conn.e2.adr, sa2, sizeof(sa2)); \
		printf("[%s]:%u => [%s]:%u : %s : t0=%lld last=t0+%lld now=last+%lld cutoff=%u packets_orig=%llu packets_reply=%llu seq0=%u rseq=%u ack0=%u rack=%u wsize_orig=%u:%d wsize_reply=%u:%d\n", \
			sa1, t->conn.e1.port, sa2, t->conn.e2.port, \
			connstate_s[t->track.state], \
			(unsigned long long)t->track.t_start, (unsigned long long)(t->track.t_last - t->track.t_start), (unsigned long long)(tnow - t->track.t_last), \
			t->track.b_cutoff, \
			(unsigned long long)t->track.pcounter_orig, (unsigned long long)t->track.pcounter_reply, \
			t->track.seq0, t->track.seq_last - t->track.seq0, t->track.ack0, t->track.ack_last - t->track.ack0, \
			t->track.winsize_orig, t->track.scale_orig==SCALE_NONE ? -1 : t->track.scale_orig, \
			t->track.winsize_reply, t->track.scale_reply==SCALE_NONE ? -1 : t->track.scale_reply ); \
	};
void ConntrackPoolDump4(t_conntrack4 *p)
{
	_ConntrackPoolDump(4,)
}
void ConntrackPoolDump6(t_conntrack6 *p)
{
	_ConntrackPoolDump(6,6)
}
void ConntrackPoolDump(t_conntrack *p)
{
	ConntrackPoolDump4(p->pool4);
	ConntrackPoolDump6(p->pool6);
}
