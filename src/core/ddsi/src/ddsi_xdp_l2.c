// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include "ddsi__xdp_l2.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/log.h"
#include "dds/ddsrt/sockets.h"
#include "dds/ddsi/ddsi_log.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "ddsi__tran.h"
#include "dds/ddsrt/static_assert.h"
#include "ddsi__userspace_l2_utils.h"

#if defined(__linux) && !LWIP_SOCKET
#include <ifaddrs.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <linux/if_ether.h>
#include <sys/resource.h>

#define NUM_FRAMES         4096
#define XDP_L2_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define XDP_L2_FRAME_DATA_SIZE (XDP_L2_FRAME_SIZE - offsetof(struct xdp_l2_packet, payload))
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

static struct xdp_program *prog;
//bool custom_xsk = false;


//struct config {
//    enum xdp_attach_mode attach_mode;
//    __u32 xdp_flags;
//    int ifindex;
//    bool do_unload;
//    __u32 prog_id;
//    bool reuse_maps;
//    char pin_dir[512];
//    char filename[512];
//    char progname[32];
//    char src_mac[18];
//    char dest_mac[18];
//    __u16 xsk_bind_flags;
//    bool xsk_poll_mode;
//    bool unload_all;
//};

//struct config cfg = {
//        .ifindex   = -1,
//};

struct xsk_umem_info {
    struct xsk_ring_prod rxFillRing;
    struct xsk_ring_cons txCompletionRing;
    struct xsk_umem *umem;
    // Actual data storage pointer, use with xsk_umem__get_data
    void *buffer;
};

struct xsk_socket_info {
    // Documentation on rings: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
    // The UMEM uses two rings: FILL and COMPLETION. Each socket associated with the UMEM must have an RX queue, TX
    // queue or both. Say, that there is a setup with four sockets (all doing TX and RX). Then there will be one FILL
    // ring, one COMPLETION ring, four TX rings and four RX rings.
	struct xsk_ring_cons rxCompletionRing;
	struct xsk_ring_prod txFillRing;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

};

typedef struct xdp_transport_factory {
    // This needs to be first field so that it can be cast as necessary
    struct ddsi_tran_factory m_base;

    struct xsk_socket_info xskSocketInfo;
    char *ifname;
    int ifindex;
    int xsk_if_queue;
    __u32 xdp_flags;
    __u16 xsk_bind_flags;
    int xsk_map_fd;
} *xdp_transport_factory_t;

//typedef struct ddsi_raweth_conn {
//    struct ddsi_tran_conn m_base;
//    ddsrt_socket_t m_sock;
//    int m_ifindex;
//} *ddsi_raweth_conn_t;

typedef struct ddsi_xdp_l2_conn {
    struct ddsi_tran_conn m_base;
    // VB: Do we need a socket?
} *ddsi_xdp_l2_conn_t;

typedef struct xdp_l2_packet {
    // An over-the-wire packet, consisting of an ethernet header and the payload.
    struct ethhdr header;
    char payload[0];
} *xdp_l2_packet_t;


static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
    r->cached_cons = *r->consumer + r->size;
    return r->cached_cons - r->cached_prod;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->rxFillRing, &umem->txCompletionRing, NULL);
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(xdp_transport_factory_t factory, struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.xdp_flags = factory->xdp_flags;
    xsk_cfg.bind_flags = factory->xsk_bind_flags;
//    xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    ret = xsk_socket__create(&xsk_info->xsk, factory->ifname,
                             factory->xsk_if_queue, umem->umem, &xsk_info->rxCompletionRing,
                             &xsk_info->txFillRing, &xsk_cfg);
    if (ret) {
        return NULL;
    }

//    if (custom_xsk) {
    ret = xsk_socket__update_xskmap(xsk_info->xsk, factory->xsk_map_fd);
    if (ret) {
        return NULL;
    }
//    } else {
//        /* Getting the program ID must be after the xdp_socket__create() call */
//        if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
//            goto error_exit;
//    }

    /* Initialize umem frame allocation */
    for (unsigned int i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * XDP_L2_FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    uint32_t rxFillRingIndex;
    ret = xsk_ring_prod__reserve(&xsk_info->umem->rxFillRing, XSK_RING_PROD__DEFAULT_NUM_DESCS, &rxFillRingIndex);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        return NULL;
    }

    for (unsigned int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++) {
        *xsk_ring_prod__fill_addr(&xsk_info->umem->rxFillRing, rxFillRingIndex) = xsk_alloc_umem_frame(xsk_info);
        rxFillRingIndex++;
    }
    xsk_ring_prod__submit(&xsk_info->umem->rxFillRing, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;
}

//static void rx_and_process(struct config *cfg, struct xsk_socket_info *xsk_socket)
//{
//    struct pollfd fds[2];
//    int ret, nfds = 1;
//
//    memset(fds, 0, sizeof(fds));
//    fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
//    fds[0].events = POLLIN;
//
//    while(!global_exit) {
//        if (cfg->xsk_poll_mode) {
//            ret = poll(fds, nfds, -1);
//            if (ret <= 0 || ret > 1)
//                continue;
//        }
//        handle_receive_packets(xsk_socket);
//    }
//}

static ssize_t ddsi_xdp_l2_conn_read (struct ddsi_tran_conn * conn, unsigned char * buf, size_t len, bool allow_spurious, ddsi_locator_t *srcloc) {
    (void) allow_spurious;
    assert(allow_spurious > 0);

    struct xsk_socket_info *xsk = &((xdp_transport_factory_t)conn->m_factory)->xskSocketInfo;
    unsigned int packetsReceived, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;
    int bytes_received = -1;


    for(uint8_t tries = 0; tries < 200; tries++) {
        packetsReceived = xsk_ring_cons__peek(&xsk->rxCompletionRing, RX_BATCH_SIZE, &idx_rx);
        if (packetsReceived > 0) {
            break;
        }
    }

    /* Stuff the ring with as many frames as possible */
    stock_frames = xsk_prod_nb_free(&xsk->umem->rxFillRing, xsk_umem_free_frames(xsk));

    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&xsk->umem->rxFillRing, stock_frames, &idx_fq);

        /* This should not happen, but just in case */
        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->rxFillRing, packetsReceived, &idx_fq);

        for (i = 0; i < stock_frames; i++) {
            *xsk_ring_prod__fill_addr(&xsk->umem->rxFillRing, idx_fq++) = xsk_alloc_umem_frame(xsk);
        }

        xsk_ring_prod__submit(&xsk->umem->rxFillRing, stock_frames);
    }

    /* Process received packets */
    for (i = 0; i < packetsReceived; i++) {
        const struct xdp_desc *rxDescriptor = xsk_ring_cons__rx_desc(&xsk->rxCompletionRing, idx_rx);
        
        if(bytes_received + rxDescriptor->len >= len) {
            assert(bytes_received > 0);
            break;
        }

        struct xdp_l2_packet *packet = (struct xdp_l2_packet *) xsk_umem__get_data(xsk->umem->buffer, rxDescriptor->addr);

        if(ddsi_userspace_l2_is_valid_ethertype(packet->header.h_proto)) {
            assert(ddsi_userspace_l2_get_port_for_ethertype(packet->header.h_proto) == srcloc->port);
            size_t data_len = DDSI_USERSPACE_GET_PAYLOAD_SIZE(rxDescriptor->len, struct xdp_l2_packet);
            memcpy(buf, packet->payload, data_len);
            bytes_received += data_len;
        }

        xsk_free_umem_frame(xsk, rxDescriptor->addr);
        idx_rx++;
    }

    // This signals that we finished processing packetsReceived packets from the rxCompletionRing,
    // freeing up the descriptor slots
    xsk_ring_cons__release(&xsk->rxCompletionRing, packetsReceived);

    /* Do we need to wake up the kernel for transmission */
    // TODO

//    } while (rc == DDS_RETCODE_INTERRUPTED);

    return bytes_received;
}

static ssize_t ddsi_xdp_l2_conn_write (struct ddsi_tran_conn * conn, const ddsi_locator_t *dst, size_t niov, const ddsrt_iovec_t *iov, uint32_t flags)
{
    ddsi_xdp_l2_conn_t uc = (ddsi_xdp_l2_conn_t) conn;
    xdp_transport_factory_t factory = (xdp_transport_factory_t) uc->m_base.m_factory;

    assert(flags == 0);
    size_t bytes_transferred = 0;

    struct xsk_socket_info *xsk = &factory->xskSocketInfo;

    /* Here we sent the packet out of the receive port. Note that
 * we allocate one entry and schedule it. Your design would be
 * faster if you do batch processing/transmission */

    uint64_t frame = xsk_alloc_umem_frame(xsk);
    if(frame == 0) {
        assert(0);
        return DDS_RETCODE_OUT_OF_RESOURCES;
    }

    uint32_t tx_idx = 0;
    uint32_t ret = xsk_ring_prod__reserve(&xsk->txFillRing, 1, &tx_idx);
    if (ret != 1) {
        /* No more transmit slots, drop the packet */
        return DDS_RETCODE_TRY_AGAIN;
    }

    xdp_l2_packet_t frame_buffer = xsk_umem__get_data(xsk->umem->buffer, tx_idx);

    // Fill the ethernet header
    assert(dst->port < UINT16_MAX);
    frame_buffer->header.h_proto = ddsi_userspace_l2_get_ethertype_for_port((uint16_t) dst->port);
    DDSRT_STATIC_ASSERT(sizeof(dst->address) == 16 && sizeof(frame_buffer->header.h_dest) == 6);
    memcpy(frame_buffer->header.h_dest, &dst->address[10], sizeof(frame_buffer->header.h_dest));
    // TODO: Source mac addr?

    // Fill the data
    size_t data_copied = ddsi_userspace_copy_iov_to_packet(niov, iov, &frame_buffer->payload, XDP_L2_FRAME_DATA_SIZE);
    if(data_copied == 0) {
        return DDS_RETCODE_OUT_OF_RESOURCES;
    }

    // Create the TX Descriptor and actually send the message
    struct xdp_desc *txDescriptor = xsk_ring_prod__tx_desc(&xsk->txFillRing, tx_idx);
    txDescriptor->addr = tx_idx;
    txDescriptor->len = DDSI_USERSPACE_GET_PACKET_SIZE(data_copied, struct xdp_l2_packet);
    xsk_ring_prod__submit(&xsk->txFillRing, 1);

    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Collect/free completed TX buffers */
    uint32_t indexTXCompletionRing;
    unsigned int completed = xsk_ring_cons__peek(
            &xsk->umem->txCompletionRing, XSK_RING_CONS__DEFAULT_NUM_DESCS, &indexTXCompletionRing
    );

    if (completed > 0) {
        for (unsigned int i = 0; i < completed; i++) {
            xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->txCompletionRing, indexTXCompletionRing));
            indexTXCompletionRing++;
        }

        xsk_ring_cons__release(&xsk->umem->txCompletionRing, completed);
    }

    return bytes_transferred;
}

static ddsrt_socket_t ddsi_dpdk_l2_conn_handle (struct ddsi_tran_base * base)
{
//    return ((ddsi_dpdk_l2_conn_t) base)->m_sock;
    // We don't have a socket and nobody should request it.
    (void) base;
//    assert(0);
    return DDSRT_INVALID_SOCKET;
}

static bool ddsi_xdp_l2_supports (const struct ddsi_tran_factory *fact, int32_t kind)
{
    (void) fact;
    return (kind == DDSI_LOCATOR_KIND_XDP_L2);
}

static userspace_l2_mac_addr get_xdp_interface_mac_address(const char* ifname) {
    userspace_l2_mac_addr address;
    int retval = ddsrt_eth_get_mac_addr(ifname, address.bytes);
    if (retval != DDS_RETCODE_OK) {
        abort();
    }
    return address;
}

static int ddsi_xdp_l2_conn_locator (struct ddsi_tran_factory * fact, struct ddsi_tran_base * base, ddsi_locator_t *loc)
{
    ddsi_xdp_l2_conn_t uc = (ddsi_xdp_l2_conn_t) base;
    (void) fact;

    loc->kind= DDSI_LOCATOR_KIND_XDP_L2;
    loc->port = uc->m_base.m_base.m_port;


    // VB: The MAC address is in the last 6 bytes, the rest is zeroes.
    userspace_l2_mac_addr addr = get_xdp_interface_mac_address(((xdp_transport_factory_t)fact)->ifname);
    DDSI_USERSPACE_COPY_MAC_ADDRESS_AND_ZERO(loc->address, 10, &addr);
    return 0;
}

static dds_return_t ddsi_xdp_l2_create_conn (struct ddsi_tran_conn **conn_out, struct ddsi_tran_factory * fact, uint32_t port, const struct ddsi_tran_qos *qos)
{
//    ddsrt_socket_t sock;
//    dds_return_t rc;
    ddsi_xdp_l2_conn_t  uc = NULL;
//    struct sockaddr_ll addr;
    bool mcast = (qos->m_purpose == DDSI_TRAN_QOS_RECV_MC);
    assert(mcast);
    struct ddsi_domaingv const * const gv = fact->gv;
    struct ddsi_network_interface const * const intf = qos->m_interface ? qos->m_interface : &gv->interfaces[0];

    /* If port is zero, need to create dynamic port */
    // TODO: It looks like raweth uses ethernet type as port number
    assert(port < UINT16_MAX);
    if(!ddsi_userspace_l2_is_valid_ethertype(ddsi_userspace_l2_get_ethertype_for_port((uint16_t) port))) {
        DDS_CERROR(&fact->gv->logconfig, "ddsi_dpdk2_l2_create_conn: DDSI requested too large port number %i.", port);
        return DDS_RETCODE_ERROR;
    }

    if ((uc = (ddsi_xdp_l2_conn_t) ddsrt_malloc (sizeof (*uc))) == NULL)
    {
//        ddsrt_close(sock);
        return DDS_RETCODE_ERROR;
    }

    memset (uc, 0, sizeof (*uc));
//    uc->m_sock = sock;
//    uc->m_ifindex = addr.sll_ifindex;
    ddsi_factory_conn_init (fact, intf, &uc->m_base);
    uc->m_base.m_base.m_port = port;
    uc->m_base.m_base.m_trantype = DDSI_TRAN_CONN;
    uc->m_base.m_base.m_multicast = mcast;
    uc->m_base.m_base.m_handle_fn = ddsi_dpdk_l2_conn_handle;
    uc->m_base.m_locator_fn = ddsi_xdp_l2_conn_locator;
    uc->m_base.m_read_fn = ddsi_xdp_l2_conn_read;
    uc->m_base.m_write_fn = ddsi_xdp_l2_conn_write;
    uc->m_base.m_disable_multiplexing_fn = 0;

    DDS_CTRACE (&fact->gv->logconfig, "ddsi_xdp_l2_create_conn %s socket port %u\n", mcast ? "multicast" : "unicast", uc->m_base.m_base.m_port);
    *conn_out = &uc->m_base;
    printf("XDP: Connection opened on port %i\n", port);
    return DDS_RETCODE_OK;
}

static void ddsi_xdp_l2_release_conn (struct ddsi_tran_conn * conn)
{
    ddsi_xdp_l2_conn_t uc = (ddsi_xdp_l2_conn_t) conn;
    DDS_CTRACE (&conn->m_base.gv->logconfig,
                "ddsi_xdp_l2_release_conn %s port %d\n",
                conn->m_base.m_multicast ? "multicast" : "unicast",
                uc->m_base.m_base.m_port);
//    ddsrt_close (uc->m_sock);
    ddsrt_free (conn);
}

static enum ddsi_locator_from_string_result ddsi_xdp_l2_address_from_string (const struct ddsi_tran_factory *tran, ddsi_locator_t *loc, const char *str)
{
    return ddsi_userspace_l2_address_from_string(tran, loc, str, DDSI_LOCATOR_KIND_XDP_L2);
}

static void ddsi_xdp_l2_deinit(struct ddsi_tran_factory * fact)
{
    xdp_transport_factory_t factory = (xdp_transport_factory_t) fact;
    DDS_CLOG (DDS_LC_CONFIG, &fact->gv->logconfig, "dpdk l2 de-initialized\n");

    /* Cleanup */
    xsk_socket__delete(factory->xskSocketInfo.xsk);
    if(factory->xskSocketInfo.umem != NULL) {
        xsk_umem__delete(factory->xskSocketInfo.umem->umem);
    }

    // VB: Remove XDP program
    struct xdp_multiprog *mp = NULL;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);

    mp = xdp_multiprog__get_from_ifindex(factory->ifindex);
    if (libxdp_get_error(mp)) {
        fprintf(stderr, "XDP: Unable to get xdp_dispatcher program: %s\n", strerror(errno));
        goto out;
    } else if (!mp) {
        fprintf(stderr, "XDP: No XDP program loaded on %s\n", factory->ifname);
        mp = NULL;
        goto out;
    }

    // VB: Unload all == true
    int err = xdp_multiprog__detach(mp);
    if (err) {
        fprintf(stderr, "XDP: Unable to detach XDP program: %s\n", strerror(-err));
        goto out;
    }

    out:
    xdp_multiprog__close(mp);

    ddsrt_free (fact);
}

static int ddsi_xdp_l2_enumerate_interfaces (struct ddsi_tran_factory * fact, enum ddsi_transport_selector transport_selector, ddsrt_ifaddrs_t **interfaces)
{
//    int afs[] = { AF_XDP, DDSRT_AF_TERM };
    (void)fact;
    (void)transport_selector;
//    return ddsrt_getifaddrs(interfaces, afs);
    userspace_l2_mac_addr addr = get_xdp_interface_mac_address(((struct xdp_transport_factory *) fact)->ifname);
    return ddsi_userspace_create_fake_interface(interfaces, &addr);
}

static int ddsi_xdp_l2_locator_from_sockaddr (const struct ddsi_tran_factory *tran, ddsi_locator_t *loc, const struct sockaddr *sockaddr)
{
    (void) tran;

    // We use a fake interface, therefore AF_UNSPEC rather than AF_XDP
    if (sockaddr->sa_family != AF_UNSPEC) {
        return -1;
    }

    loc->kind = DDSI_LOCATOR_KIND_XDP_L2;
    loc->port = DDSI_LOCATOR_PORT_INVALID;
    DDSRT_STATIC_ASSERT(sizeof(loc->address) == sizeof(sockaddr->sa_data) + 2);
    memset (loc->address, 0, 2);
    memcpy (loc->address + 2, sockaddr->sa_data, sizeof(sockaddr->sa_data));
    return 0;
}


int ddsi_xdp_l2_init (struct ddsi_domaingv *gv)
{
    struct xdp_transport_factory *fact = ddsrt_malloc (sizeof (*fact));
    memset (fact, 0, sizeof (*fact));
    fact->m_base.gv = gv;
    fact->m_base.m_free_fn = ddsi_xdp_l2_deinit;
    fact->m_base.m_typename = XDP_FACTORY_TYPE_NAME;
    fact->m_base.m_default_spdp_address = "xdp_l2/ff:ff:ff:ff:ff:ff";
    fact->m_base.m_connless = 1;
    fact->m_base.m_enable_spdp = 1;
    fact->m_base.m_supports_fn = ddsi_xdp_l2_supports;
    fact->m_base.m_create_conn_fn = ddsi_xdp_l2_create_conn;
    fact->m_base.m_release_conn_fn = ddsi_xdp_l2_release_conn;
    fact->m_base.m_join_mc_fn = ddsi_userspace_l2_join_mc;
    fact->m_base.m_leave_mc_fn = ddsi_userspace_l2_leave_mc;
    fact->m_base.m_is_loopbackaddr_fn = ddsi_userspace_l2_is_loopbackaddr;
    fact->m_base.m_is_mcaddr_fn = ddsi_userspace_l2_is_mcaddr;
    fact->m_base.m_is_ssm_mcaddr_fn = ddsi_userspace_l2_is_ssm_mcaddr;
    fact->m_base.m_is_nearby_address_fn = ddsi_userspace_l2_is_nearby_address;
    fact->m_base.m_locator_from_string_fn = ddsi_xdp_l2_address_from_string;
    fact->m_base.m_locator_to_string_fn = ddsi_userspace_l2_locator_to_string;
    fact->m_base.m_enumerate_interfaces_fn = ddsi_xdp_l2_enumerate_interfaces;
    fact->m_base.m_is_valid_port_fn = ddsi_userspace_l2_is_valid_port_fn;
    fact->m_base.m_receive_buffer_size_fn = ddsi_userspace_l2_receive_buffer_size_fn;
    fact->m_base.m_locator_from_sockaddr_fn = ddsi_xdp_l2_locator_from_sockaddr;
    ddsi_factory_add (gv, (struct ddsi_tran_factory *) fact);
    GVLOG (DDS_LC_CONFIG, "xdp_l2 initialized\n");


    // XDP setup
    void *packet_buffer;
    uint64_t packet_buffer_size;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
//    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;
    int err;
    char errmsg[1024];

    fact->ifname = strdup("eno2");
    fact->ifindex = if_nametoindex(fact->ifname);


//    /* Load custom program if configured */
//    if (cfg.filename[0] != 0) {
//        struct bpf_map *map;
//
//        custom_xsk = true;
//        xdp_opts.open_filename = cfg.filename;
//        xdp_opts.prog_name = cfg.progname;
//        xdp_opts.opts = &opts;
//
//        if (cfg.progname[0] != 0) {
//            xdp_opts.open_filename = cfg.filename;
//            xdp_opts.prog_name = cfg.progname;
//            xdp_opts.opts = &opts;
//
//            prog = xdp_program__create(&xdp_opts);
//        } else {
//            prog = xdp_program__open_file(cfg.filename, NULL, &opts);
//        }
    prog = xdp_program__open_file("ddsi_xdp_l2_kern.o", NULL, &opts);
    err = libxdp_get_error(prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "XDP: error loading program: %s\n", errmsg);
        return err;
    }
    fprintf(stderr, "XDP: BPF program loaded.\n");

    err = xdp_program__attach(prog, fact->ifindex, XDP_MODE_SKB, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "XDP: Couldn't attach XDP program on iface '%s' : %s (%d)\n", fact->ifname, errmsg, err);
        return err;
    }
    fprintf(stderr, "XDP: Program attached to %s.\n", fact->ifname);

    /* We also need to load the xsks_map */
    struct bpf_map *map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
    fact->xsk_map_fd = bpf_map__fd(map);
    if (fact->xsk_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(fact->xsk_map_fd));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "XDP: Found xsks_map with file descriptor %i.\n", fact->xsk_map_fd);
//    }

    /* Allow unlimited locking of memory, so all memory needed for packet
     * buffers can be locked.
     */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * XDP_L2_FRAME_SIZE;
    /* PAGE_SIZE aligned */
    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Initialize shared packet_buffer for umem usage */
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (umem == NULL) {
        fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Open and configure the AF_XDP (xsk) socket */
    xsk_socket = xsk_configure_socket(fact, umem);
    if (xsk_socket == NULL) {
        fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "XDP: Initialization success!\n");
    return DDS_RETCODE_OK;
}

#else

int ddsi_raweth_init (struct ddsi_domaingv *gv) { (void) gv; return 0; }

#endif /* defined __linux */
