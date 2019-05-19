/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __OPAL_INTERNAL_H
#define __OPAL_INTERNAL_H

/****** Internal header for OPAL API related things in skiboot **********/

#include <skiboot.h>

/* An opal table entry */
struct opal_table_entry {
	void	*func;
	u32	token;
	u32	nargs;
};

#define opal_call(__tok, __func, __nargs)				\
static struct opal_table_entry __e_##__func __used __section(".opal_table") = \
{ .func = __func, .token = __tok,					\
  .nargs = __nargs + 0 * sizeof(__func( __test_args##__nargs )) }

/* Make sure function takes args they claim.  Look away now... */
#define __test_args0
#define __test_args1 0
#define __test_args2 0,0
#define __test_args3 0,0,0
#define __test_args4 0,0,0,0
#define __test_args5 0,0,0,0,0
#define __test_args6 0,0,0,0,0,0
#define __test_args7 0,0,0,0,0,0,0

extern struct opal_table_entry __opal_table_start[];
extern struct opal_table_entry __opal_table_end[];

extern uint64_t opal_pending_events;

extern struct dt_node *opal_node;

extern void opal_table_init(void);
extern void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values);
__be64 opal_dynamic_event_alloc(void);
void opal_dynamic_event_free(__be64 event);
extern void add_opal_node(void);

#define opal_register(token, func, nargs)				\
	__opal_register((token) + 0*sizeof(func(__test_args##nargs)),	\
			(func), (nargs))
extern void __opal_register(uint64_t token, void *func, unsigned num_args);

/* Warning: no locking at the moment, do at init time only
 *
 * XXX TODO: Add the big RCU-ish "opal API lock" to protect us here
 * which will also be used for other things such as runtime updates
 */
extern void opal_add_poller(void (*poller)(void *data), void *data);
extern void opal_del_poller(void (*poller)(void *data));
extern void opal_run_pollers(void);

/*
 * Warning: no locking, only call that from the init processor
 */
extern void opal_add_host_sync_notifier(bool (*notify)(void *data), void *data);
extern void opal_del_host_sync_notifier(bool (*notify)(void *data));

/*
 * Opal internal function prototype
 */
struct OpalHMIEvent;
extern int handle_hmi_exception(__be64 hmer, struct OpalHMIEvent *hmi_evt);
extern int occ_msg_queue_occ_reset(void);

#endif /* __OPAL_INTERNAL_H */
