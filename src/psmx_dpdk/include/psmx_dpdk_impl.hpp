// Copyright(c) 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <stdbool.h>

#if defined (__cplusplus)
extern "C" {
#endif

#include "dds/dds.h"
#include "dds/ddsc/dds_loan.h"
#include "dds/ddsc/dds_psmx.h"

DDS_EXPORT dds_return_t dpdk_create_psmx (
  struct dds_psmx **psmx,
  dds_loan_origin_type_t identifier,
  const char *config);

#if defined (__cplusplus)
}
#endif
