#include "params.h"
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

const char *progname = "tpws";

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

typedef void (*f_log_function)(int priority, const char *line);

static char log_buf[1024];
static size_t log_buf_sz=0;
static void syslog_log_function(int priority, const char *line)
{
	syslog(priority,"%s",log_buf);
}
#ifdef __ANDROID__
static enum android_LogPriority syslog_priority_to_android(int priority)
{
	enum android_LogPriority ap;
	switch(priority)
	{
		case LOG_INFO:
		case LOG_NOTICE: ap=ANDROID_LOG_INFO; break;
		case LOG_ERR: ap=ANDROID_LOG_ERROR; break;
		case LOG_WARNING: ap=ANDROID_LOG_WARN; break;
		case LOG_EMERG:
		case LOG_ALERT:
		case LOG_CRIT: ap=ANDROID_LOG_FATAL; break;
		case LOG_DEBUG: ap=ANDROID_LOG_DEBUG; break;
		default: ap=ANDROID_LOG_UNKNOWN;
	}
	return ap;
}
static void android_log_function(int priority, const char *line)
{
	__android_log_print(syslog_priority_to_android(priority), progname, "%s", line);
}
#endif
static void log_buffered(f_log_function log_function, int syslog_priority, const char *format, va_list args)
{
	if (vsnprintf(log_buf+log_buf_sz,sizeof(log_buf)-log_buf_sz,format,args)>0)
	{
		log_buf_sz=strlen(log_buf);
		// log when buffer is full or buffer ends with \n
		if (log_buf_sz>=(sizeof(log_buf)-1) || (log_buf_sz && log_buf[log_buf_sz-1]=='\n'))
		{
			log_function(syslog_priority,log_buf);
			log_buf_sz = 0;
		}
	}
}

static int DLOG_VA(const char *format, int syslog_priority, bool condup, int level, va_list args)
{
	int r=0;
	va_list args2;

	if (condup && !(params.debug>=level && params.debug_target==LOG_TARGET_CONSOLE))
	{
		va_copy(args2,args);
		DLOG_CON(format,syslog_priority,args2);
		va_end(args2);
	}
	if (params.debug>=level)
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
				log_buffered(syslog_log_function,syslog_priority,format,args);
				r = 1;
				break;
#ifdef __ANDROID__
			case LOG_TARGET_ANDROID:
				// skip newlines
				log_buffered(android_log_function,syslog_priority,format,args);
				r = 1;
				break;
#endif
			default:
				break;
		}
	}
	return r;
}

int DLOG(const char *format, int level, ...)
{
	int r;
	va_list args;
	va_start(args, level);
	r = DLOG_VA(format, LOG_DEBUG, false, level, args);
	va_end(args);
	return r;
}
int DLOG_CONDUP(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_DEBUG, true, 1, args);
	va_end(args);
	return r;
}
int DLOG_ERR(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_ERR, true, 1, args);
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

void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit)
{
	size_t k;
	bool bcut = false;
	if (size > limit)
	{
		size = limit;
		bcut = true;
	}
	if (!size) return;
	for (k = 0; k < size; k++) VPRINT("%02X ", data[k]);
	VPRINT(bcut ? "... : " : ": ");
	for (k = 0; k < size; k++) VPRINT("%c", data[k] >= 0x20 && data[k] <= 0x7F ? (char)data[k] : '.');
	if (bcut) VPRINT(" ...");
}

void dp_init(struct desync_profile *dp)
{
	LIST_INIT(&dp->hl_collection);
	LIST_INIT(&dp->hl_collection_exclude);
	LIST_INIT(&dp->ips_collection);
	LIST_INIT(&dp->ips_collection_exclude);
	LIST_INIT(&dp->pf_tcp);

	dp->filter_ipv4 = dp->filter_ipv6 = true;
	memcpy(dp->hostspell, "host", 4); // default hostspell
	dp->hostlist_auto_fail_threshold = HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT;
	dp->hostlist_auto_fail_time = HOSTLIST_AUTO_FAIL_TIME_DEFAULT;
}

struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head)
{
	struct desync_profile_list *entry = calloc(1,sizeof(struct desync_profile_list));
	if (!entry) return NULL;

	dp_init(&entry->dp);

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
static void dp_clear_dynamic(struct desync_profile *dp)
{
	hostlist_collection_destroy(&dp->hl_collection);
	hostlist_collection_destroy(&dp->hl_collection_exclude);
	ipset_collection_destroy(&dp->ips_collection);
	ipset_collection_destroy(&dp->ips_collection_exclude);
	port_filters_destroy(&dp->pf_tcp);
	HostFailPoolDestroy(&dp->hostlist_auto_fail_counters);
}
void dp_clear(struct desync_profile *dp)
{
	dp_clear_dynamic(dp);
	memset(dp,0,sizeof(*dp));
}
void dp_entry_destroy(struct desync_profile_list *entry)
{
	dp_clear_dynamic(&entry->dp);
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


#if !defined( __OpenBSD__) && !defined(__ANDROID__)
void cleanup_args(struct params_s *params)
{
	wordfree(&params->wexp);
}
#endif
void cleanup_params(struct params_s *params)
{
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	cleanup_args(params);
#endif

	dp_list_destroy(&params->desync_profiles);

	hostlist_files_destroy(&params->hostlists);
	ipset_files_destroy(&params->ipsets);
	ipcacheDestroy(&params->ipcache);
	free(params->user); params->user=NULL;
}
