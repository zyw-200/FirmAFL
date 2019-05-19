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

#define pr_fmt(fmt) "opalmsg: " fmt
#include <skiboot.h>
#include <opal-msg.h>
#include <opal-api.h>
#include <lock.h>

#define OPAL_MAX_MSGS		(OPAL_MSG_TYPE_MAX + OPAL_MAX_ASYNC_COMP - 1)

struct opal_msg_entry {
	struct list_node link;
	void (*consumed)(void *data);
	void *data;
	struct opal_msg msg;
};

static LIST_HEAD(msg_free_list);
static LIST_HEAD(msg_pending_list);

static struct lock opal_msg_lock = LOCK_UNLOCKED;

int _opal_queue_msg(enum opal_msg_type msg_type, void *data,
		    void (*consumed)(void *data), size_t num_params,
		    const u64 *params)
{
	struct opal_msg_entry *entry;

	lock(&opal_msg_lock);

	entry = list_pop(&msg_free_list, struct opal_msg_entry, link);
	if (!entry) {
		prerror("No available node in the free list, allocating\n");
		entry = zalloc(sizeof(struct opal_msg_entry));
		if (!entry) {
			prerror("Allocation failed\n");
			unlock(&opal_msg_lock);
			return OPAL_RESOURCE;
		}
	}

	entry->consumed = consumed;
	entry->data = data;
	entry->msg.msg_type = cpu_to_be32(msg_type);

	if (num_params > ARRAY_SIZE(entry->msg.params)) {
		prerror("Discarding extra parameters\n");
		num_params = ARRAY_SIZE(entry->msg.params);
	}
	memcpy(entry->msg.params, params, num_params*sizeof(u64));

	list_add_tail(&msg_pending_list, &entry->link);
	opal_update_pending_evt(OPAL_EVENT_MSG_PENDING,
				OPAL_EVENT_MSG_PENDING);

	unlock(&opal_msg_lock);

	return 0;
}

static int64_t opal_get_msg(uint64_t *buffer, uint64_t size)
{
	struct opal_msg_entry *entry;
	void (*callback)(void *data);
	void *data;

	if (size < sizeof(struct opal_msg) || !buffer)
		return OPAL_PARAMETER;

	lock(&opal_msg_lock);

	entry = list_pop(&msg_pending_list, struct opal_msg_entry, link);
	if (!entry) {
		unlock(&opal_msg_lock);
		return OPAL_RESOURCE;
	}

	memcpy(buffer, &entry->msg, sizeof(entry->msg));
	callback = entry->consumed;
	data = entry->data;

	list_add(&msg_free_list, &entry->link);
	if (list_empty(&msg_pending_list))
		opal_update_pending_evt(OPAL_EVENT_MSG_PENDING, 0);

	unlock(&opal_msg_lock);

	if (callback)
		callback(data);

	return OPAL_SUCCESS;
}
opal_call(OPAL_GET_MSG, opal_get_msg, 2);

static int64_t opal_check_completion(uint64_t *buffer, uint64_t size,
				     uint64_t token)
{
	struct opal_msg_entry *entry, *next_entry;
	void (*callback)(void *data) = NULL;
	int rc = OPAL_BUSY;
	void *data = NULL;

	lock(&opal_msg_lock);
	list_for_each_safe(&msg_pending_list, entry, next_entry, link) {
		if (entry->msg.msg_type == OPAL_MSG_ASYNC_COMP &&
		    be64_to_cpu(entry->msg.params[0]) == token) {
			list_del(&entry->link);
			callback = entry->consumed;
			data = entry->data;
			list_add(&msg_free_list, &entry->link);
			if (list_empty(&msg_pending_list))
				opal_update_pending_evt(OPAL_EVENT_MSG_PENDING,
							0);
			rc = OPAL_SUCCESS;
			break;
		}
	}

	if (rc == OPAL_SUCCESS && size >= sizeof(struct opal_msg))
		memcpy(buffer, &entry->msg, sizeof(entry->msg));

	unlock(&opal_msg_lock);

	if (callback)
		callback(data);

	return rc;

}
opal_call(OPAL_CHECK_ASYNC_COMPLETION, opal_check_completion, 3);

void opal_init_msg(void)
{
	struct opal_msg_entry *entry;
	int i;

	for (i = 0; i < OPAL_MAX_MSGS; i++, entry++) {
                entry = zalloc(sizeof(*entry));
                if (!entry)
                        goto err;
		list_add_tail(&msg_free_list, &entry->link);
        }
        return;

err:
        for (; i > 0; i--) {
                entry = list_pop(&msg_free_list, struct opal_msg_entry, link);
                if (entry)
                        free(entry);
        }
}

