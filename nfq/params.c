#include "params.h"

#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#include "pools.h"
#include "desync.h"

#ifdef BSD
const char *progname = "dvtws";
#elif defined(__CYGWIN__)
const char *progname = "winws";
#elif defined(__linux__)
const char *progname = "nfqws";
#else
#error UNKNOWN_SYSTEM_TIME
#endif


int DLOG_FILE(FILE *F, const char *format, va_list args)
{
	return vfprintf(F, format, args);
}
int DLOG_CON(const char *format, int syslog_priority, va_list args)
{
	return DLOG_FILE(syslog_priority==LOG_ERR ? stderr : stdout, format, args);
}
int DLOG_FILENAME(const char *filename, const char *format, va_list args)
{
	int r;
	FILE *F = fopen(filename,"at");
	if (F)
	{
		r = DLOG_FILE(F, format, args);
		fclose(F);
	}
	else
		r=-1;
	return r;
}

static char syslog_buf[1024];
static size_t syslog_buf_sz=0;
static void syslog_buffered(int priority, const char *format, va_list args)
{
	if (vsnprintf(syslog_buf+syslog_buf_sz,sizeof(syslog_buf)-syslog_buf_sz,format,args)>0)
	{
		syslog_buf_sz=strlen(syslog_buf);
		// log when buffer is full or buffer ends with \n
		if (syslog_buf_sz>=(sizeof(syslog_buf)-1) || (syslog_buf_sz && syslog_buf[syslog_buf_sz-1]=='\n'))
		{
			syslog(priority,"%s",syslog_buf);
			syslog_buf_sz = 0;
		}
	}
}

static int DLOG_VA(const char *format, int syslog_priority, bool condup, va_list args)
{
	int r=0;
	va_list args2;

	if (condup && !(params.debug && params.debug_target==LOG_TARGET_CONSOLE))
	{
		va_copy(args2,args);
		DLOG_CON(format,syslog_priority,args2);
	}
	if (params.debug)
	{
		switch(params.debug_target)
		{
			case LOG_TARGET_CONSOLE:
				r = DLOG_CON(format,syslog_priority,args);
				break;
			case LOG_TARGET_FILE:
				r = DLOG_FILENAME(params.debug_logfile,format,args);
				break;
			case LOG_TARGET_SYSLOG:
				// skip newlines
				syslog_buffered(syslog_priority,format,args);
				r = 1;
				break;
			default:
				break;
		}
	}
	return r;
}

int DLOG(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_DEBUG, false, args);
	va_end(args);
	return r;
}
int DLOG_CONDUP(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_DEBUG, true, args);
	va_end(args);
	return r;
}
int DLOG_ERR(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_ERR, true, args);
	va_end(args);
	return r;
}
int DLOG_PERROR(const char *s)
{
	return DLOG_ERR("%s: %s\n", s, strerror(errno));
}


int LOG_APPEND(const char *filename, const char *format, va_list args)
{
	int r;
	FILE *F = fopen(filename,"at");
	if (F)
	{
		fprint_localtime(F);
		fprintf(F, " : ");
		r = vfprintf(F, format, args);
		fprintf(F, "\n");
		fclose(F);
	}
	else
		r=-1;
	return r;
}

int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...)
{
	if (*params.hostlist_auto_debuglog)
	{
		int r;
		va_list args;

		va_start(args, format);
		r = LOG_APPEND(params.hostlist_auto_debuglog, format, args);
		va_end(args);
		return r;
	}
	else
		return 0;
}


struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head)
{
	struct desync_profile_list *entry = calloc(1,sizeof(struct desync_profile_list));
	if (!entry) return NULL;
	
	LIST_INIT(&entry->dp.hostlist_files);
	LIST_INIT(&entry->dp.hostlist_exclude_files);
	memcpy(entry->dp.hostspell, "host", 4); // default hostspell
	entry->dp.desync_skip_nosni = true;
	entry->dp.desync_split_pos = 2;
	entry->dp.desync_ipfrag_pos_udp = IPFRAG_UDP_DEFAULT;
	entry->dp.desync_ipfrag_pos_tcp = IPFRAG_TCP_DEFAULT;
	entry->dp.desync_repeats = 1;
	entry->dp.fake_tls_size = sizeof(fake_tls_clienthello_default);
	memcpy(entry->dp.fake_tls,fake_tls_clienthello_default,entry->dp.fake_tls_size);
	randomize_default_tls_payload(entry->dp.fake_tls);
	entry->dp.fake_http_size = strlen(fake_http_request_default);
	memcpy(entry->dp.fake_http,fake_http_request_default,entry->dp.fake_http_size);
	entry->dp.fake_quic_size = 620; // must be 601+ for TSPU hack
	entry->dp.fake_quic[0] = 0x40; // russian TSPU QUIC short header fake
	entry->dp.fake_wg_size = 64;
	entry->dp.fake_dht_size = 64;
	entry->dp.fake_unknown_size = 256;
	entry->dp.fake_syndata_size = 16;
	entry->dp.fake_unknown_udp_size = 64;
	entry->dp.wscale=-1; // default - dont change scale factor (client)
	entry->dp.desync_ttl6 = 0xFF; // unused
	entry->dp.desync_badseq_increment = BADSEQ_INCREMENT_DEFAULT;
	entry->dp.desync_badseq_ack_increment = BADSEQ_ACK_INCREMENT_DEFAULT;
	entry->dp.wssize_cutoff_mode = entry->dp.desync_start_mode = entry->dp.desync_cutoff_mode = 'n'; // packet number by default
	entry->dp.udplen_increment = UDPLEN_INCREMENT_DEFAULT;
	entry->dp.hostlist_auto_fail_threshold = HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT;
	entry->dp.hostlist_auto_fail_time = HOSTLIST_AUTO_FAIL_TIME_DEFAULT;
	entry->dp.hostlist_auto_retrans_threshold = HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT;
	entry->dp.filter_ipv4 = entry->dp.filter_ipv6 = true;

	// add to the tail
	struct desync_profile_list *dpn,*dpl=LIST_FIRST(&params.desync_profiles);
	if (dpl)
	{
		while ((dpn=LIST_NEXT(dpl,next))) dpl = dpn;
		LIST_INSERT_AFTER(dpl, entry, next);
	}
	else
		LIST_INSERT_HEAD(&params.desync_profiles, entry, next);

	return entry;
}
static void dp_entry_destroy(struct desync_profile_list *entry)
{
	strlist_destroy(&entry->dp.hostlist_files);
	strlist_destroy(&entry->dp.hostlist_exclude_files);
	strlist_destroy(&entry->dp.ipset_files);
	strlist_destroy(&entry->dp.ipset_exclude_files);
	StrPoolDestroy(&entry->dp.hostlist_exclude);
	StrPoolDestroy(&entry->dp.hostlist);
	ipsetDestroy(&entry->dp.ips);
	ipsetDestroy(&entry->dp.ips_exclude);
	HostFailPoolDestroy(&entry->dp.hostlist_auto_fail_counters);
	free(entry);
}
void dp_list_destroy(struct desync_profile_list_head *head)
{
	struct desync_profile_list *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		dp_entry_destroy(entry);
	}
}
bool dp_list_have_autohostlist(struct desync_profile_list_head *head)
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, head, next)
		if (*dpl->dp.hostlist_auto_filename)
			return true;
	return false;
}

