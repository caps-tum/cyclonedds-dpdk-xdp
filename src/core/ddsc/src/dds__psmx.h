/*
 * Copyright(c) 2022 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#ifndef DDS__PSMX_H
#define DDS__PSMX_H

#include "dds/ddsi/ddsi_sertype.h"
#include "dds/ddsc/dds_psmx.h"
#include "dds/ddsc/dds_public_impl.h"

struct ddsi_domaingv;
struct dds_domain;
struct dds_ktopic;
struct dds_endpoint;

DDSRT_STATIC_ASSERT (sizeof (dds_psmx_data_type_properties_t) == sizeof (ddsi_data_type_properties_t));

/* linked list describing a number of topics */
struct dds_psmx_topic_list_elem {
  struct dds_psmx_topic * topic; /*the current element in the list*/
  struct dds_psmx_topic_list_elem * prev; /*the previous element in the list*/
  struct dds_psmx_topic_list_elem * next; /*the next element in the list*/
};

/* linked list describing a number of endpoints */
struct dds_psmx_endpoint_list_elem {
  struct dds_psmx_endpoint * endpoint; /*the current element in the list*/
  struct dds_psmx_endpoint_list_elem * prev; /*the previous element in the list*/
  struct dds_psmx_endpoint_list_elem * next; /*the next element in the list*/
};

struct dds_psmx_endpoint * dds_psmx_create_endpoint (struct dds_psmx_topic *topic, dds_psmx_endpoint_type_t endpoint_type);

dds_return_t dds_psmx_delete_endpoint (struct dds_psmx_endpoint *psmx_endpoint);

/**
 * @brief Definition for the function to load a PSMX instance
 *
 * This function is exported from the PSMX plugin library.
 *
 * @returns a DDS return code
 */
typedef dds_return_t (*dds_psmx_create_fn) (
  struct dds_psmx **pubsub_message_exchange, /*output for the PSMX instance to be created*/
  dds_loan_origin_type_t identifier, /*the unique identifier for this PSMX*/
  const char *config /*PSMX specific configuration*/
);

dds_return_t dds_pubsub_message_exchange_init (const struct ddsi_domaingv *gv, struct dds_domain *domain);

dds_return_t dds_pubsub_message_exchange_fini (struct dds_domain *domain);

dds_return_t dds_endpoint_open_psmx_endpoint (struct dds_endpoint *ep, const dds_qos_t *qos, struct dds_psmx_topics_set *psmx_topics, dds_psmx_endpoint_type_t endpoint_type);
struct ddsi_psmx_locators_set *dds_get_psmx_locators_set (const dds_qos_t *qos, const struct dds_psmx_set *psmx_instances);
void dds_psmx_locators_set_free (struct ddsi_psmx_locators_set *psmx_locators);

#endif // DDS__PSMX_H
