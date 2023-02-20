#include <cassert>
#include <iostream>
#include <sstream>

#include <signal.h>

#include "pin.H"
#include "threadstate.hpp"
#include "utils.hpp"
#include "libreassure.hpp"
#include "watchdog.hpp"
#include "log.hpp"
#include "reassure.h"
#include "libcrossdev.hpp"
#include "debug.h"

//! Add signal that causes exit to this base and exit process with this code
#define SIGEXITCODE_BASE	128

//! Timeout option string
#define TIMEOUT_OPTION 		"timeout"


#ifdef TARGET_LINUX

extern "C" {
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
}

#define gettid()		syscall(SYS_gettid)
#define tkill(p, s)		syscall(SYS_tkill, (p), (s))
#define tgkill(pp, p, s)	syscall(SYS_tgkill, (pp), (p), (s))

/**
 * Use fork() to perform checkpoints and simply mark the written memory
 * addresses.
 */
static KNOB<BOOL> fork_checkpoint(KNOB_MODE_WRITEONCE, "pintool", "f", "1",
		"Use fork to perform checkpoints. Faster for most "
		"types of checkpoints.");

#endif // TARGET_LINUX


//! For correct watchdog support for children
static struct command_line {
        int argc;
        char **argv;
} cmdln;


#ifdef COLLECT_STATS
static unsigned long long stats_checkpoints, //!< No checkpoints performed
		     stats_commits,  	     //!< No of committed checkpoints
		     stats_rollbacks;	     //!< No of rolled back checkpoints
#endif

//! Rescue points configuration 
static KNOB<string> config_file(KNOB_MODE_WRITEONCE, "pintool", "c", 
		"reassure.conf", "REASSURE configuration file.");

//! Set type of blocking rescue points
static KNOB<BOOL> runtime_block(KNOB_MODE_WRITEONCE, "pintool", "rb", 
		"1", "Use runtime blocks for blocking rescue points. Faster "
		"for non-rescue point code, but slower when blocking rescue "
		"points occur extremely often.");

//! Original name
static KNOB<string> original_name(KNOB_MODE_WRITEONCE, "pintool",
    "n", "", "Specify executable's original name. For reporting errors.");

//! Timeout in seconds (we exit if execution takes more than this value)
KNOB<unsigned long long> exec_timeout(KNOB_MODE_WRITEONCE, "pintool",
                TIMEOUT_OPTION, "0", "Timeout in seconds. Stop executing "
                "after specified amount of seconds). 0 disables timeout.");

//! Reference Id
static KNOB<string> ref_id(KNOB_MODE_WRITEONCE, "pintool",
    "ref", "", "Specify reference-id. For reporting errors.");

//! Notification messages to stderr
static KNOB<bool> notify_stderr(KNOB_MODE_WRITEONCE, "pintool",
    "notify", "0", "Notification messages are also written to stderr.");



//////////////////
// Helper
//////////////////

static VOID usage(void)
{
	cout << "This is the RE-ASSURE tool, implementing Rescue Points for"
		" binaries" << endl;
	cout << KNOB_BASE::StringKnobSummary() << endl;
}

#if 0
static void ReportDoS(stringstream &ss)
{
        ss << "<structured_message>" << endl;
        ss << "\t<message_type>technical_impact" << "</message_type>" << endl;
        ss << "\t<impact>" << "DOS_INSTABILITY" << "</impact>" << endl;
        ss << "\t<test_case>" << original_name.Value() << "</test_case>" 
		<< endl;
        ss << "</structured_message>" << endl;
}
#endif

static VOID append_tc(stringstream &ss)
{
	ss << "\t<test_case>" << original_name.Value() << "</test_case>" << endl;
	ss << "\t<ref_id>" << ref_id.Value() << "</ref_id>" << endl;
}

static inline VOID notify(stringstream &ss)
{
	if (notify_stderr.Value()) {
		ERRLOG(ss);
	} else {
		OUTLOG(ss);
	}
	ss.str("");
}

static void minestrone_notify(THREADID tid, const EXCEPTION_INFO *pExceptInfo)
{
	stringstream ss;
	EXCEPTION_CODE code; 
	ADDRINT fault_addr;

#if 0
        if (reassure_threadstate(tid) == ROLLINGBACK) {
                // Something went terribly wrong during recovery
                ss << "<structured_message>" << endl;
                ss << "\t<message_type>controlled_exit" <<
                        "</message_type>" << endl;
                ss << "\t<test_case>" << original_name.Value() << 
			"</test_case>" << endl;
                ss << "</structured_message>" << endl;

                ReportDoS(ss);

                ss << "MINESTRONE LOG STOP" << endl <<
                        "Recovery failed!" << endl;
		NOTIFY(ss);

                PIN_ExitProcess(1);
        }
#endif

        if (!pExceptInfo)
                goto noinfo;

        code = PIN_GetExceptionCode(pExceptInfo);
        if (PIN_GetExceptionClass(code) != EXCEPTCLASS_ACCESS_FAULT) {
                goto noinfo;
        }

        if (!PIN_GetFaultyAccessAddress(pExceptInfo, &fault_addr)) {
                goto noinfo;
        }

	// Report null pointer dereference
        if (fault_addr == 0) {
                ss << "<structured_message>" << endl;
                ss << "\t<message_type>found_cwe</message_type>" << endl;
		append_tc(ss);
                // CWE-476 NULL Pointer Dereference
                ss << "\t<cwe_entry_id>476</cwe_entry_id>" << endl;
                ss << "</structured_message>" << endl;
        }

noinfo:
	// Report technical_impact
        ss << "<structured_message>" << endl;
        ss << "\t<message_type>technical_impact" << "</message_type>" << endl;
        ss << "\t<impact>" << "DOS_INSTABILITY" << "</impact>" << endl;
	append_tc(ss);
        ss << "\t<test_case>" << original_name.Value() << "</test_case>" << endl;
        ss << "</structured_message>" << endl;
	notify(ss);
}

void log_exec_status(exis_status_t status, INT32 code)
{
	stringstream ss;

	// Execute status
	ss << "<return_status_message>" << endl;
	ss << "\t<message_type>execute_status" << "</message_type>" << endl;
	append_tc(ss);
	switch (status) {
	case ES_SUCCESS:
		ss << "\t<status>success</status>" << endl;
		ss << "\t<status_code>" << code << "</status_code>" << endl;
		break;

	case ES_TIMEOUT:
		ss << "\t<status>timeout</status>" << endl;
		break;

	case ES_SKIP:
		ss << "\t<status>skip</status>" << endl;
		break;

	}
	ss << "</return_status_message>" << endl;
	notify(ss);
}

/**
 * Generic fault handler for both external and Pin internal faults.
 *
 * @param tid		Thread id that received the fault
 * @param code		Interger code corresponding to the fault
 * @param ctx		Pointer to current CPU state
 * @param has_handler	True if the application has a handler installed
 * @param info		Pointer to exception information
 * @param internal	True if its an internal fault
 * @param res		Result of reassure handling the fault
 *
 * @return true if recovery was triggered, or false otherwise
 */
static BOOL gen_fault_handler(THREADID tid, INT32 code, const CONTEXT *ctx, 
		BOOL has_handler, const EXCEPTION_INFO *info, BOOL internal, 
		reassure_ehandling_result_t res)
{
	BOOL handled;

	switch (res) {
	case RHR_HANDLED:
		handled = TRUE;
		break;
	
	case RHR_RESCUED:
		minestrone_notify(tid, info);
		if (internal)
			PIN_ExecuteAt(ctx);
		handled = TRUE;
		break;

	case RHR_ERROR:
	default:
		handled = FALSE;
		if (!internal && has_handler)
			break;
		code += SIGEXITCODE_BASE;
		log_exec_status(ES_SUCCESS, code);
		if (info)
			cerr << PIN_ExceptionToString(info) << endl;
		PIN_ExitProcess(code);
	}

	return handled;
}

/**
 * Handle a Pin internal fault.
 *
 * @param tid	Pin thread id
 * @param info	Additional information 
 * @param pctx	Physical CPU state
 * @param v 	Opaque value passed by the call back
 *
 * @return EHR_HANDLED if the fault was successfully handled, or EHR_UNHANDLED
 * otherwise
 */
static EXCEPT_HANDLING_RESULT internal_fault_handler(THREADID tid, 
		EXCEPTION_INFO *info, PHYSICAL_CONTEXT *pctx, VOID *v)
{
	CONTEXT ctx;
	reassure_ehandling_result_t res;

#ifdef SIGNAL_DEBUG
	string desc;
	stringstream ss;

	desc = (info)? PIN_ExceptionToString(info) : "<unknown>";
	ss << "PIN [" << tid << "] received internal fault: " << desc << endl;
#endif

	res = reassure_handle_internal_fault(tid, &ctx, info);
	if (gen_fault_handler(tid, SIGSEGV, &ctx, FALSE, info, TRUE, res))
		return EHR_HANDLED;
	return EHR_UNHANDLED;
}

#ifdef TARGET_LINUX
/**
 * Handle a signal that would cause the application to terminate.
 *
 * @param tid Pin thread id
 * @param sig Signal number 
 * @param ctx CPU state
 * @param has_handler True if the application has a handler installed
 * @param info Additional information 
 * @param v Opaque value passed by the call back
 *
 * @return FALSE if the signal was successfully handled, and should be ignored
 * by the application, TRUE otherwise
 */
static BOOL sig_fault_handler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL has_handler, const EXCEPTION_INFO *info, VOID *v)
{
	reassure_ehandling_result_t res;

#ifdef SIGNAL_DEBUG
	string desc;
	stringstream ss;

	desc = (info)? PIN_ExceptionToString(info) : "<unknown>";
	ss << "PIN [" << tid << "] received internal fault: " << desc << endl;
#endif

	res = reassure_handle_fault(tid, ctx);
	if (gen_fault_handler(tid, sig, ctx, has_handler, info, FALSE, res))
		return FALSE; // Handled
	return TRUE; // Not handled, deliver
}
#endif

#ifdef TARGET_WINDOWS
/**
 * Handle context changes (which according to Pin includes exceptions, APCs, 
 * etc
 *
 * @param tid 		Pin thread id
 * @param reason 	Context change reason
 * @param from 		CPU state before the callback
 * @param to 		CPU state after the callback (may be changed from call)
 * @param info 		Additional information on reason
 * @param v 		Opaque value passed by the call back
 */
static VOID ctx_change_handler(THREADID tid, CONTEXT_CHANGE_REASON reason,
		const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{

	// We are only interested in Windows exception.
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION) {
		EXCEPTION_INFO einfo;
		reassure_ehandling_result_t res;
#ifdef SIGNAL_DEBUG
		stringstream ss;

		PIN_InitWindowsExceptionInfo(&einfo, info,
				PIN_GetContextReg(from, REG_INST_PTR));
		ss << "PIN [" << tid << "] " << PIN_ExceptionToString(&einfo) 
			<< endl;
		DBGLOG(ss);
#endif

		if (!to) {
			stringstream ss;
			ss << "PIN[ " << tid << "] Exception does not have "
				"future state." << endl <<
				"This is probably a fatal exception" << endl;
			OUTLOG(ss);
			return;
		}

		res = reassure_handle_fault(tid, to);
		gen_fault_handler(tid, info, to, TRUE, &einfo, FALSE, res);
	}
}
#endif

// Linked to ThreadStart and global variable initialization
static VOID fork_handler(THREADID tid, const CONTEXT *ctx, VOID *v)
{
        // Start watchdog for new process, if necessary
        if (exec_timeout.Value() > 0) {
                if (!WatchdogStart())
                        PIN_ExitProcess(EXIT_FAILURE);
        }

#ifdef FORK_DEBUG
	{
		stringstream ss;

		ss << "fork_handlered process pid " << PIN_GetPid() << endl;
		DBGLOG(ss);
	}
#endif
}

static VOID save_cmd_line(int argc, char **argv) 
{ 
        int i; 
        char *argv_copy; 
 
        cmdln.argc = argc; 
        cmdln.argv = (char **)malloc((argc + 1) * sizeof(char **)); 
        ASSERT(cmdln.argv, "Error allocating memory for command line "
			"arguments array\n"); 
 
        for (i = 0; i < argc; i++) {
                argv_copy = strdup(argv[i]); 
                ASSERT(argv_copy, "Error allocating memory for command line "
				" arguments\n");
                //cout << "ARG[" << i << "]=" << argv_copy << endl; 
                cmdln.argv[i] = argv_copy; 
        } 
        cmdln.argv[i] = NULL; 
}

static BOOL exec_handler(CHILD_PROCESS child, VOID *v)
{
        int i;
	stringstream ss;

        if (exec_timeout.Value() == 0)
                return TRUE;

        for (i = 0; i < cmdln.argc; i++) {
                // Stop looking if we reached the application's arguments
                if (strcmp(cmdln.argv[i], "--") == 0)
                        break;
                // Look for the timeout option
                if (strcmp(cmdln.argv[i], "-"TIMEOUT_OPTION) == 0) {
                        if (++i >= cmdln.argc) {
				ss << "No timeout option found in exec'ed "
					"child's command line" << endl;
				ERRLOG(ss);
                                PIN_ExitProcess(EXIT_FAILURE);
                        }
			ss << WatchdogRemaining();
#ifdef TARGET_LINUX
                        cmdln.argv[i] = strdup(ss.str().c_str());
#endif
#ifdef TARGET_WINDOWS
			cmdln.argv[i] = _strdup(ss.str().c_str());
#endif
                        break;
                }
        }

        CHILD_PROCESS_SetPinCommandLine(child, cmdln.argc, cmdln.argv);
        return TRUE;
}

static VOID fini(INT32 code, VOID *v)
{
	log_exec_status(ES_SUCCESS, code);
}


int main(int argc, char **argv)
{
	bool usefork;

	// This is needed to access functions by name
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		usage();
		return EXIT_FAILURE;
	}

#ifdef TARGET_LINUX
	usefork = fork_checkpoint.Value();
	PIN_UnblockSignal(SIGSEGV, TRUE);
	PIN_InterceptSignal(SIGSEGV, sig_fault_handler, 0);
	PIN_UnblockSignal(SIGILL, TRUE);
	PIN_InterceptSignal(SIGILL, sig_fault_handler, 0);
	PIN_UnblockSignal(SIGABRT, TRUE);
	PIN_InterceptSignal(SIGABRT, sig_fault_handler, 0);
	PIN_UnblockSignal(SIGFPE, TRUE);
	PIN_InterceptSignal(SIGFPE, sig_fault_handler, 0);
	PIN_UnblockSignal(SIGPIPE, TRUE);
	PIN_InterceptSignal(SIGPIPE, sig_fault_handler, 0);
#else
	PIN_AddContextChangeFunction(ctx_change_handler, 0);
	usefork = false;
#endif

	if (reassure_init(config_file.Value().c_str(),
				runtime_block.Value(), usefork) != 0)
		return EXIT_FAILURE;

	PIN_AddInternalExceptionHandler(internal_fault_handler, 0);

	// If a timeout has been specified, setup and start the watchdog
        if (exec_timeout.Value() > 0) {
                save_cmd_line(argc, argv);
                WatchdogInit(exec_timeout.Value());
#ifdef TARGET_LINUX
		PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, fork_handler, 0);
#endif
                PIN_AddFollowChildProcessFunction(exec_handler, NULL);
                if (!WatchdogStart())
                        return EXIT_FAILURE;
        }
	
	PIN_AddFiniFunction(fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
