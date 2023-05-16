#include <stdio.h>
#include "ddsi__userspace_l2_utils.h"
#include <dds/ddsi/ddsi_protocol.h>
#include "ddsi__tran.h"

// Addressing utilities

char *ddsi_userspace_l2_locator_to_string(char *dst, size_t sizeof_dst, const ddsi_locator_t *loc,
                                          struct ddsi_tran_conn *conn, int with_port) {
    (void) conn;
    if (with_port)
        (void) snprintf(dst, sizeof_dst, "[%02x:%02x:%02x:%02x:%02x:%02x]:%u",
                        loc->address[10], loc->address[11], loc->address[12],
                        loc->address[13], loc->address[14], loc->address[15], loc->port);
    else
        (void) snprintf(dst, sizeof_dst, "[%02x:%02x:%02x:%02x:%02x:%02x]",
                        loc->address[10], loc->address[11], loc->address[12],
                        loc->address[13], loc->address[14], loc->address[15]);
    return dst;
}

enum ddsi_locator_from_string_result ddsi_userspace_l2_address_from_string(
        const struct ddsi_tran_factory *tran, ddsi_locator_t *loc, const char *str, int32_t locatorKind) {
    // VB: MAC Address parsing should be ok. Check if we want to set port to something
    int i = 0;
    (void) tran;
    loc->kind = locatorKind;
    loc->port = DDSI_LOCATOR_PORT_INVALID;
    memset(loc->address, 0, sizeof(loc->address));
    while (i < 6 && *str != 0) {
        unsigned o;
        int p;
        if (sscanf(str, "%x%n", &o, &p) != 1 || o > 255)
            return AFSR_INVALID;
        loc->address[10 + i++] = (unsigned char) o;
        str += p;
        if (i < 6) {
            if (*str != ':')
                return AFSR_INVALID;
            str++;
        }
    }
    if (*str)
        return AFSR_INVALID;
    return AFSR_OK;
}

int ddsi_userspace_l2_is_loopbackaddr(const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc) {
    (void) tran;
    (void) loc;
    return 0;
}

int ddsi_userspace_l2_is_mcaddr(const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc) {
    (void) tran;
    assert (loc->kind == DDSI_LOCATOR_KIND_DPDK_L2 || loc->kind == DDSI_LOCATOR_KIND_XDP_L2);
    return (loc->address[10] & 1);
}

int ddsi_userspace_l2_is_ssm_mcaddr(const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc) {
    (void) tran;
    (void) loc;
    return 0;
}

enum ddsi_nearby_address_result ddsi_userspace_l2_is_nearby_address(
        const ddsi_locator_t *loc, size_t ninterf, const struct ddsi_network_interface *interf, size_t *interf_idx) {
    (void) ninterf;
    // VB: This looks up only the address of the first interface.
    // TODO: OK? Depends on if ddsi_network_interface is reliable
    if (interf_idx)
        *interf_idx = 0;
    if (memcmp(interf[0].loc.address, loc->address, sizeof(loc->address)) == 0)
        return DNAR_SELF;
    else
        return DNAR_LOCAL;
}


// Multicast groups


static int isbroadcast(const ddsi_locator_t *loc) {
    // VB: This should be OK as is.
    int i;
    for (i = 0; i < 6; i++) {
        if (loc->address[10 + i] != 0xff) {
            return 0;
        }
    }
    return 1;
}

//static int joinleave_asm_mcgroup (ddsrt_socket_t socket, int join, const ddsi_locator_t *mcloc, const struct ddsi_network_interface *interf)
//{
//    int rc;
//    struct packet_mreq mreq;
//    mreq.mr_ifindex = (int)interf->if_index;
//    mreq.mr_type = PACKET_MR_MULTICAST;
//    mreq.mr_alen = 6;
//    memcpy(mreq.mr_address, mcloc + 10, 6);
//    rc = ddsrt_setsockopt(socket, SOL_PACKET, join ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
//    return (rc == DDS_RETCODE_OK) ? 0 : rc;
//}

int ddsi_userspace_l2_join_mc(struct ddsi_tran_conn *conn, const ddsi_locator_t *srcloc, const ddsi_locator_t *mcloc,
                              const struct ddsi_network_interface *interf) {
    if (isbroadcast(mcloc))
        return 0;
    else {
        // VB: Multicast groups unsupported for now
        (void) conn;
        (void) srcloc;
        (void) interf;
        assert(false);
        return DDS_RETCODE_UNSUPPORTED;
//        ddsi_raweth_conn_t uc = (ddsi_raweth_conn_t) conn;
//        (void)srcloc;
//        return joinleave_asm_mcgroup(uc->m_sock, 1, mcloc, interf);
    }
}

int ddsi_userspace_l2_leave_mc(struct ddsi_tran_conn *conn, const ddsi_locator_t *srcloc, const ddsi_locator_t *mcloc,
                               const struct ddsi_network_interface *interf) {
    if (isbroadcast(mcloc))
        return 0;
    else {
        // VB: Multicast groups unsupported for now
        (void) conn;
        (void) srcloc;
        (void) interf;
        assert(false);
        return DDS_RETCODE_UNSUPPORTED;
//        ddsi_raweth_conn_t uc = (ddsi_raweth_conn_t) conn;
//        (void)srcloc;
//        return joinleave_asm_mcgroup(uc->m_sock, 0, mcloc, interf);
    }
}
