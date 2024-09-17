#include "params.h"
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

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
	return DLOG_FILE(syslog_priority == LOG_ERR ? stderr : stdout, format, args);
}
int DLOG_FILENAME(const char *filename, const char *format, va_list args)
{
	int r;
	FILE *F = fopen(filename, "at");
	if (F)
	{
		r = DLOG_FILE(F, format, args);
		fclose(F);
	}
	else
		r = -1;
	return r;
}

static char syslog_buf[1024];
static size_t syslog_buf_sz = 0;
static void syslog_buffered(int priority, const char *format, va_list args)
{
	if (vsnprintf(syslog_buf + syslog_buf_sz, sizeof(syslog_buf) - syslog_buf_sz, format, args) > 0)
	{
		syslog_buf_sz = strlen(syslog_buf);
		// log when buffer is full or buffer ends with \n
		if (syslog_buf_sz >= (sizeof(syslog_buf) - 1) || (syslog_buf_sz && syslog_buf[syslog_buf_sz - 1] == '\n'))
		{
			syslog(priority, "%s", syslog_buf);
			syslog_buf_sz = 0;
		}
	}
}

static int DLOG_VA(const char *format, int syslog_priority, bool condup, va_list args)
{
	int r = 0;
	va_list args2;

	if (condup && !(params.debug && params.debug_target == LOG_TARGET_CONSOLE))
	{
		va_copy(args2, args);
		DLOG_CON(format, syslog_priority, args2);
	}
	if (params.debug)
	{
		switch (params.debug_target)
		{
		case LOG_TARGET_CONSOLE:
			r = DLOG_CON(format, syslog_priority, args);
			break;
		case LOG_TARGET_FILE:
			r = DLOG_FILENAME(params.debug_logfile, format, args);
			break;
		case LOG_TARGET_SYSLOG:
			// skip newlines
			syslog_buffered(syslog_priority, format, args);
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
	FILE *F = fopen(filename, "at");
	if (F)
	{
		fprint_localtime(F);
		fprintf(F, " : ");
		r = vfprintf(F, format, args);
		fprintf(F, "\n");
		fclose(F);
	}
	else
		r = -1;
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
