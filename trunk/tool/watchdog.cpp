#include <iostream>
#include <sstream>
#include <cassert>

#ifdef TARGET_LINUX
extern "C" {
#include <stdlib.h>
}
#endif

#include <time.h>

#include "pin.H"
#include "watchdog.hpp"
#include "log.hpp"
#include "reassure.h"

// Semaphore used for sleeping
static PIN_SEMAPHORE sem;
// Creation time
static time_t epoch;
// Timeout
static time_t timeout;


time_t WatchdogRemaining()
{
	time_t nepoch, lifetime;

	time(&nepoch);
	lifetime = nepoch - epoch;

	if (lifetime < timeout)
		return (timeout - lifetime);
	return 0;
}

// Wait until timeout elapses, or until process terminates
static VOID WatchdogRun(void *arg)
{
	time_t nepoch, lifetime;

	time(&nepoch);
	// XXX: Switch this to a monotonous timer
	ASSERT(nepoch >= epoch, "Current time is in the past\n");
	lifetime = nepoch - epoch;

	// Check that we have not already exceeded the allowed run time
	if (lifetime < timeout) {
		/* wait until the application is exiting or a timeout has 
		 * occurred */
		if (PIN_SemaphoreTimedWait(&sem, 
					1000 * (unsigned)(timeout - lifetime)))
			return; // Application is terminating
	}

	// If the process is exiting, don't consider this as a timeout
	if (!PIN_IsProcessExiting()) {
		  /* 
                 * emit the necessary XML message for the
                 * test harness and terminate the process
                 */
		log_exec_status(ES_TIMEOUT, EXIT_FAILURE);

                /* terminate */
                PIN_ExitProcess(EXIT_FAILURE);
	}
}

// Stop the watchdog by setting the semaphore
static VOID WatchdogStop(INT32 code, VOID *v)
{
	PIN_SemaphoreSet(&sem);
}

VOID WatchdogInit(unsigned long long tmout)
{
	PIN_SemaphoreInit(&sem);
	time(&epoch);
	timeout = tmout;

	PIN_AddFiniUnlockedFunction(WatchdogStop, NULL);
}

BOOL WatchdogStart()
{
	THREADID watchdog_tid;
	
	watchdog_tid = PIN_SpawnInternalThread(WatchdogRun, NULL, 0, NULL);
	if (watchdog_tid == INVALID_THREADID) {
		ERRLOG("cannot start watchdog thread");
		return FALSE;
	}

	return TRUE;
}

