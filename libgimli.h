/*
 * Copyright (c) 2008-2010 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#ifndef LIBGIMLI_H
#define LIBGIMLI_H

#include <signal.h>

/* This header file defines the interface that a child process may optionally
 * use to notify the gimli monitor process that it is up and running and in a
 * healthy condition.
 * If the signal handlers are not established, the monitor will still be able
 * to respawn the child in the case of an abnormal terminator, but may not be
 * able to obtain trace information.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct gimli_heartbeat;

/** While state has this value, it means that the child process
 * won't be beating its heart.  This may change later in its lifetime.
 */
#define GIMLI_HB_NOT_SUPP 0

 /** child is starting up */
#define GIMLI_HB_STARTING 1

/** child is running, heart beating normally */
#define GIMLI_HB_RUNNING 2

/** child is stopping, heart may beat slower */
#define GIMLI_HB_STOPPING 3

/** returns the heartbeat segment passed down to us from the monitor.
 * May return NULL.  If the segment was found, sets the state to
 * STARTING.
 * Implicitly calls gimli_establish_signal_handlers()
 */
volatile struct gimli_heartbeat *gimli_heartbeat_attach(void);

/** Sets up the signal handlers to arrange for tracing in the event of a fault.
 * This is usually called as part of the gimli_heartbeat_attach()
 * call, but is broken out here in case your application links against
 * a library (such as Java) that changes your signal handlers unconditionally.
 * If that scenario applies to your application, you should call
 * gimli_establish_signal_handlers() after initializing any/all such
 * libraries.
 */
void gimli_establish_signal_handlers(void);

/** modifies the heartbeat state, and increment the ticks */
void gimli_heartbeat_set(volatile struct gimli_heartbeat *hb, int state);

/** the prototype of a function to be called before terminating in the
 * event of receiving a fatal signal. */
typedef void (*gimli_shutdown_func_t)(int signo, siginfo_t *si);

/** register a shutdown function */
void gimli_set_shutdown_func(gimli_shutdown_func_t func);

#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

