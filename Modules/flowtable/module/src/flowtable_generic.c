/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#pragma GCC optimize (4)
#include "flowtable/flowtable.h"
#include "flowtable/flowtable_generic.h"
#include "murmur/murmur.h"
#include "flowtable_log.h"

#define FLOWTABLE_GENERIC_BUCKETS 32

/*
 * flowtable_generic hash with flowtable_entry mask as key
 */
struct flowtable_generic {
    struct list_head generic_buckets[FLOWTABLE_GENERIC_BUCKETS];
};

/*
 * An entry in a flowtable generic.
 *
 * flowtable_generic_entry will be removed if the flow_cnt reaches zero.
 */
struct flowtable_generic_entry {
    struct list_links links;
    struct flowtable_key flow_mask;
    struct flowtable *ft;
    uint32_t flow_cnt;  /* Number of flow entries in flowtable */
};


static struct list_head *generic_flow_bucket(struct flowtable_generic *ft, const struct flowtable_entry *fte);

/*
 * HACK need a random number to prevent hash collision attacks.
 */
extern uint32_t ind_ovs_salt;

/* Documented in flowtable_generic.h */
struct flowtable_generic *
flowtable_generic_create()
{
    struct flowtable_generic *ftg = malloc(sizeof(*ftg));
    if (ftg == NULL) {
        return NULL;
    }

    int i;
    for (i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        list_init(&ftg->generic_buckets[i]);
    }

    return ftg;
}

/* Documented in flowtable_generic.h */
void
flowtable_generic_destroy(struct flowtable_generic *ftg)
{
    struct list_links *cur;
    int i;

    for(i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        while((cur = list_pop(&ftg->generic_buckets[i])) != NULL) {
            struct flowtable_generic_entry *cur_ftge =
                container_of(cur, links, struct flowtable_generic_entry);

            flowtable_destroy(cur_ftge->ft);
            free(cur_ftge);
        }
    }

    free(ftg);
    return;
}

/* Documented in flowtable_generic.h */
void
flowtable_generic_insert(struct flowtable_generic *ftg, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct list_head *bucket = generic_flow_bucket(ftg, fte);

    /* Check if same flow mask entry is present in the table */
    LIST_FOREACH(bucket, cur) {
        struct flowtable_generic_entry *cur_ftge =
            container_of(cur, links, struct flowtable_generic_entry);
        if (memcmp(&cur_ftge->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            /* If present, insert the new flow table entry */
            flowtable_insert(cur_ftge->ft, fte);
            cur_ftge->flow_cnt++;
            return;
        }
    }

    /* If not present, then create a new flowtable and insert flowmask hash table */
    struct flowtable *ft = flowtable_create(&fte->mask);
    if(ft == NULL) {
        AIM_LOG_ERROR("no memory for flowtable !!");
        return;
    }

    struct flowtable_generic_entry *ftge_new = calloc(1, sizeof(*ftge_new));
    if(ftge_new == NULL) {
        AIM_LOG_ERROR("no memory for flowtable generic entry !!");
        free(ft);
        return;
    }

    ftge_new->flow_mask = fte->mask;
    ftge_new->ft = ft;
    flowtable_insert(ft, fte);
    ftge_new->flow_cnt = 1;

    list_push(bucket, &ftge_new->links);
    return;
}

/* Documented in flowtable_generic.h */
void
flowtable_generic_remove(struct flowtable_generic *ftg, struct flowtable_entry *fte)
{
    struct list_links *cur;
    struct flowtable_generic_entry *cur_ftge = NULL;
    struct list_head *bucket = generic_flow_bucket(ftg, fte);

    /* Find the flow table generic entry to update the flow_cnt */
    LIST_FOREACH(bucket, cur) {
        cur_ftge = container_of(cur, links, struct flowtable_generic_entry);
        if (memcmp(&cur_ftge->flow_mask, &fte->mask, sizeof(struct flowtable_key)) == 0) {
            break;
        }
        cur_ftge = NULL;
    }

    if(cur_ftge) {
        cur_ftge->flow_cnt--;
        list_remove(&fte->links);

        /* If no flow are present then destroy the flow table and
           free the flowtable_genric entry */
        if(!cur_ftge->flow_cnt) {
            free(cur_ftge->ft);
            list_remove(&cur_ftge->links);
            free(cur_ftge);
        }
    }

    return;
}

/* Documented in flowtable_generic.h */
struct flowtable_entry *
flowtable_generic_match(struct flowtable_generic *ftg,
                        const struct flowtable_key *key)
{
    struct flowtable_generic_entry *cur_ftge = NULL;
    struct list_links *cur = NULL;
    struct flowtable_entry *found = NULL;
    struct flowtable_entry *new_found = NULL;
    int i = 0;

    /* Check all the flowtables for the flow table entry with highest priority */
    for(i = 0; i < FLOWTABLE_GENERIC_BUCKETS; i++) {
        LIST_FOREACH(&ftg->generic_buckets[i], cur) {
            cur_ftge = container_of(cur, links, struct flowtable_generic_entry);
            new_found = flowtable_match(cur_ftge->ft, key);

            if(new_found != NULL) {
                if(found == NULL) {
                    found = new_found;
                    continue;
                }
                else if(found->priority < new_found->priority){
                    found = new_found;
                }
            }
        }
    }

    return found;
}

/*
 * Return the generic bucket for the given flowtable entry
 */
static struct list_head *
generic_flow_bucket(struct flowtable_generic *ftg, const struct flowtable_entry *fte)
{
    struct flowtable_key masked_key;
    memcpy(&masked_key, &fte->mask, sizeof(struct flowtable_key));
    uint32_t hash = murmur_hash(&masked_key, sizeof(masked_key), ind_ovs_salt);
    return &ftg->generic_buckets[hash % FLOWTABLE_GENERIC_BUCKETS];
}
