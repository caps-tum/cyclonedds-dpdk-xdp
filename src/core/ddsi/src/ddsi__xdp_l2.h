// Copyright(c) 2006 to 2020 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__XDP_L2_H
#define DDSI__XDP_L2_H

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_domaingv;

#define XDP_FACTORY_TYPE_NAME "xdp_l2"
/** @component raw_ethernet_transport */
int ddsi_xdp_l2_init (struct ddsi_domaingv *gv);

#if defined (__cplusplus)
}
#endif

#endif /* DDSI__XDP_L2_H */
