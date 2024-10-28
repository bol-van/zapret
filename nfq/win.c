#ifdef __CYGWIN__

#include <windows.h>

#include "win.h"
#include "nfqws.h"

#define SERVICE_NAME "winws"

static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus = NULL;
static int service_argc = 0;
static char **service_argv = NULL;

void service_main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)));

bool service_run(int argc, char *argv[])
{
	SERVICE_TABLE_ENTRY ServiceTable[] = {
		{SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
		{NULL, NULL}
	};

	service_argc = argc;
	service_argv = argv;

	return StartServiceCtrlDispatcherA(ServiceTable);
}

static void service_set_status(DWORD state)
{
	ServiceStatus.dwCurrentState = state;
	SetServiceStatus(hStatus, &ServiceStatus);
}

// Control handler function
void service_controlhandler(DWORD request)
{
	switch (request)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		bQuit = true;
		ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		break;
	}
	SetServiceStatus(hStatus, &ServiceStatus);
}

void service_main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 1;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandlerA(
		SERVICE_NAME,
		(LPHANDLER_FUNCTION)service_controlhandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		// Registering Control Handler failed
		return;
	}

	SetServiceStatus(hStatus, &ServiceStatus);

	// Calling main with saved argc & argv
	ServiceStatus.dwWin32ExitCode = (DWORD)main(service_argc, service_argv);

	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(hStatus, &ServiceStatus);
	return;
}


#endif
