/*
 * Copyright (c) 2008-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifndef LIBGIMLI_H
#define LIBGIMLI_H

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

#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

