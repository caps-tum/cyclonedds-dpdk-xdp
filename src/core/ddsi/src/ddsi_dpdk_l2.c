// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include "ddsi__dpdk_l2.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/log.h"
#include "dds/ddsrt/sockets.h"
#include "dds/ddsi/ddsi_log.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "ddsi__tran.h"
#include "ddsi__raweth.h"
#include "ddsi__ipaddr.h"
#include "ddsi__mcgroup.h"
#include "ddsi__pcap.h"
#include "dds/ddsrt/static_assert.h"

#if defined(__linux) && !LWIP_SOCKET
#include <linux/if_packet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_hash_crc.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024


#define DPDK_L2_ETHER_TYPE 0x88B5
typedef struct dpdk_l2_packet {
    // An over-the-wire packet, consisting of an ethernet header and the payload.
    struct rte_ether_hdr header;
    char payload[0];
} *dpdk_l2_packet_t;

static uint16_t calculate_payload_size(struct rte_mbuf *const buf) {
    // Get the length of the actual payload excluding the space required for the header.
    if(buf->data_len == 0) {
        return 0;
    }
    assert(buf->data_len > offsetof(struct dpdk_l2_packet, payload));
    DDSRT_STATIC_ASSERT(offsetof(struct dpdk_l2_packet, payload) < UINT16_MAX);
    return buf->data_len - (uint16_t)offsetof(struct dpdk_l2_packet, payload);
}

typedef struct dpdk_transport_factory {
    // This needs to be first field so that it can be cast as necessary
    struct ddsi_tran_factory m_base;

    uint16_t dpdk_port_identifier;
    struct rte_mempool *m_dpdk_memory_pool_tx;
    struct rte_mempool *m_dpdk_memory_pool_rx;
} *dpdk_transport_factory_t;

//typedef struct ddsi_raweth_conn {
//    struct ddsi_tran_conn m_base;
//    ddsrt_socket_t m_sock;
//    int m_ifindex;
//} *ddsi_raweth_conn_t;

typedef struct ddsi_dpdk_l2_conn {
    struct ddsi_tran_conn m_base;
    // VB: Do we need a socket?
    uint16_t m_dpdk_queue_identifier;
} *ddsi_dpdk_l2_conn_t;

static char *ddsi_dpdk_l2_to_string (char *dst, size_t sizeof_dst, const ddsi_locator_t *loc, struct ddsi_tran_conn * conn, int with_port)
{
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

static void copy_mac_address_and_zero(void* dest, size_t offset, struct rte_ether_addr *addr) {
    // Zeros all bytes from dest to dest + offset (exclusive), copies the MAC address to dest + offset.
    // User is responsible for ensuring that there is sufficient space.
    memset(dest, 0, offset);
    memcpy(dest + offset, addr->addr_bytes, sizeof(struct rte_ether_addr));
}


static ssize_t ddsi_dpdk_l2_conn_read (struct ddsi_tran_conn * conn, unsigned char * buf, size_t len, bool allow_spurious, ddsi_locator_t *srcloc) {
//    struct msghdr msghdr;
//    struct sockaddr_ll src;
//    struct iovec msg_iov;
//    socklen_t srclen = (socklen_t) sizeof (src);
    (void) allow_spurious;
    assert(allow_spurious > 0);

//    msg_iov.iov_base = (void*) buf;
//    msg_iov.iov_len = len;
//
//    memset (&msghdr, 0, sizeof (msghdr));
//
//    msghdr.msg_name = &src;
//    msghdr.msg_namelen = srclen;
//    msghdr.msg_iov = &msg_iov;
//    msghdr.msg_iovlen = 1;

//    do {
//        rc = ddsrt_recvmsg(((ddsi_dpdk_l2_conn_t) conn)->m_sock, &msghdr, 0, &bytes_received);
    /* Get burst of RX packets, from first port of pair. */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(((dpdk_transport_factory_t) conn->m_factory)->m_dpdk_memory_pool_rx);
    uint16_t number_received;
    ssize_t bytes_received;
    uint8_t tries = 0;
    while (true) {
        number_received = rte_eth_rx_burst(
                ((dpdk_transport_factory_t) conn->m_factory)->dpdk_port_identifier, 0, &mbuf, 1
        );
        if (number_received > 0) {
            break;
        }
        if (tries >= 5) {
            bytes_received = DDS_RETCODE_TRY_AGAIN;
            break;
        }
        rte_delay_us_block(100);
        tries++;
    }
    if (number_received == 1) {

        dpdk_l2_packet_t packet = rte_pktmbuf_mtod(mbuf, dpdk_l2_packet_t);
        uint16_t payload_size = calculate_payload_size(mbuf);
        if(payload_size <= len) {
            memcpy(buf, packet->payload, payload_size);
            bytes_received = payload_size;
        } else {
            bytes_received = DDS_RETCODE_TRY_AGAIN;
        }

        if (srcloc)
        {
            srcloc->kind = DDSI_LOCATOR_KIND_DPDK_L2;
//            srcloc->port = ntohs (src.sll_protocol);
            DDSRT_STATIC_ASSERT(
                    sizeof(srcloc->address) == sizeof(packet->header.s_addr) + 10
            );
            copy_mac_address_and_zero(srcloc->address, 10, &packet->header.s_addr);
            assert(packet->header.ether_type >= DPDK_L2_ETHER_TYPE);
            srcloc->port = packet->header.ether_type - DPDK_L2_ETHER_TYPE;
        }

        printf("DPDK: Read complete (port %i, %zi bytes: %02x %02x %02x ... %02x %02x %02x, CRC: %x).\n",
               srcloc->port, bytes_received,
               buf[0], buf[1], buf[2], buf[bytes_received-3], buf[bytes_received-2], buf[bytes_received-1],
               rte_hash_crc(packet->payload, bytes_received, 1337)
        );
        assert(conn->m_base.m_port == srcloc->port);
    }
    rte_pktmbuf_free(mbuf);

//    } while (rc == DDS_RETCODE_INTERRUPTED);

    return bytes_received;
}

unsigned char bcast_locator[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static bool dpdk_l2_is_broadcast_locator(const ddsi_locator_t *locator) {
    assert(locator->kind == DDSI_LOCATOR_KIND_DPDK_L2);
    DDSRT_STATIC_ASSERT(sizeof(bcast_locator) == sizeof(locator->address));

    return memcmp(locator->address, bcast_locator, sizeof(locator->address)) == 0;
}

static ssize_t ddsi_dpdk_l2_conn_write (struct ddsi_tran_conn * conn, const ddsi_locator_t *dst, size_t niov, const ddsrt_iovec_t *iov, uint32_t flags)
{
    ddsi_dpdk_l2_conn_t uc = (ddsi_dpdk_l2_conn_t) conn;
    dpdk_transport_factory_t factory = (dpdk_transport_factory_t) uc->m_base.m_factory;
    dds_return_t rc;
//    unsigned retry = 2;
//    int sendflags = 0;
//    struct msghdr msg;
//    struct sockaddr_ll dstaddr;
    assert(niov <= INT_MAX);
//    memset (&dstaddr, 0, sizeof (dstaddr));
//    dstaddr.sll_family = AF_PACKET;
//    dstaddr.sll_protocol = htons ((uint16_t) dst->port);
//    dstaddr.sll_ifindex = uc->m_dpdk_port_identifier;
//    dstaddr.sll_halen = 6;
//    memcpy(dstaddr.sll_addr, dst->address + 10, 6);
//    memset(&msg, 0, sizeof(msg));
//    msg.msg_name = &dstaddr;
//    msg.msg_namelen = sizeof(dstaddr);
//    msg.msg_flags = (int) flags;
//    msg.msg_iov = (ddsrt_iovec_t *) iov;
//    msg.msg_iovlen = niov;
//#ifdef MSG_NOSIGNAL
//    sendflags |= MSG_NOSIGNAL;
//#endif
    // TODO: Determine how we should filter packets.
//    assert(dpdk_l2_is_broadcast_locator(dst));

    assert(flags == 0);
    size_t bytes_transferred = 0;

    size_t total_iov_size = 0;
    for(size_t i = 0; i < niov; i++) {
        total_iov_size += iov[i].iov_len;
    }

    struct rte_mbuf *buf = rte_pktmbuf_alloc(factory->m_dpdk_memory_pool_tx);
    assert(total_iov_size < UINT16_MAX - sizeof(struct dpdk_l2_packet));
    dpdk_l2_packet_t data_loc = (dpdk_l2_packet_t) rte_pktmbuf_append(
            buf, (uint16_t) sizeof(struct dpdk_l2_packet) + (uint16_t) total_iov_size
    );
    assert(data_loc);
    assert(dst->port < UINT16_MAX);
    data_loc->header.ether_type = DPDK_L2_ETHER_TYPE + (uint16_t)dst->port;
    // VB: Source address: Current interface mac address. Destination address: Broadcast.
    rte_eth_macaddr_get(0, &data_loc->header.s_addr);
    memset(data_loc->header.d_addr.addr_bytes, 0xFF, sizeof(data_loc->header.d_addr.addr_bytes));

    for(size_t i = 0; i < niov; i++) {
        memcpy(data_loc->payload + bytes_transferred, iov[i].iov_base, iov[i].iov_len);
        bytes_transferred += iov[i].iov_len;
    }

    int transmitted = rte_eth_tx_burst(factory->dpdk_port_identifier, uc->m_dpdk_queue_identifier, &buf, 1);
    if(transmitted != 1) {
        return DDS_RETCODE_TRY_AGAIN;
    }

    printf("DPDK: Write complete (port %i, %zu iovs, %zi bytes: %02x %02x %02x ... %02x %02x %02x, CRC: %x).\n",
           dst->port, niov, bytes_transferred,
           data_loc->payload[0], data_loc->payload[1], data_loc->payload[2], data_loc->payload[bytes_transferred-3], data_loc->payload[bytes_transferred-2], data_loc->payload[bytes_transferred-1],
           rte_hash_crc(data_loc->payload, bytes_transferred, 1337)
    );

    rte_pktmbuf_free(buf);
    rc = DDS_RETCODE_OK;
    return (rc == DDS_RETCODE_OK ? (ssize_t) bytes_transferred : -1);
}

static ddsrt_socket_t ddsi_dpdk_l2_conn_handle (struct ddsi_tran_base * base)
{
//    return ((ddsi_dpdk_l2_conn_t) base)->m_sock;
    // We don't have a socket and nobody should request it.
    (void) base;
//    assert(0);
    return DDSRT_INVALID_SOCKET;
}

static bool ddsi_dpdk_l2_supports (const struct ddsi_tran_factory *fact, int32_t kind)
{
    (void) fact;
    return (kind == DDSI_LOCATOR_KIND_DPDK_L2);
}

static struct rte_ether_addr get_dpdk_interface_mac_address(uint16_t portId) {
    struct rte_ether_addr addr;
    int retval = rte_eth_macaddr_get(portId, &addr);
    if (retval != 0) {
        assert(false);
    }
    return addr;
}

static int ddsi_dpdk_l2_conn_locator (struct ddsi_tran_factory * fact, struct ddsi_tran_base * base, ddsi_locator_t *loc)
{
    ddsi_dpdk_l2_conn_t uc = (ddsi_dpdk_l2_conn_t) base;
    (void) fact;

    loc->kind= DDSI_LOCATOR_KIND_DPDK_L2;
    loc->port = uc->m_base.m_base.m_port;


    // VB: The MAC address is in the last 6 bytes, the rest is zeroes.
    DDSRT_STATIC_ASSERT(sizeof(loc->address) == sizeof(struct rte_ether_addr) + 10);
    struct rte_ether_addr addr = get_dpdk_interface_mac_address(((dpdk_transport_factory_t)fact)->dpdk_port_identifier);
    copy_mac_address_and_zero(loc->address, 10, &addr);
    return 0;
}

static dds_return_t ddsi_dpdk_l2_create_conn (struct ddsi_tran_conn **conn_out, struct ddsi_tran_factory * fact, uint32_t port, const struct ddsi_tran_qos *qos)
{
//    ddsrt_socket_t sock;
//    dds_return_t rc;
    ddsi_dpdk_l2_conn_t  uc = NULL;
//    struct sockaddr_ll addr;
    bool mcast = (qos->m_purpose == DDSI_TRAN_QOS_RECV_MC);
    assert(mcast);
    struct ddsi_domaingv const * const gv = fact->gv;
    struct ddsi_network_interface const * const intf = qos->m_interface ? qos->m_interface : &gv->interfaces[0];

    /* If port is zero, need to create dynamic port */

//    if (port == 0 || port > 65535)
//    {
//        DDS_CERROR (&fact->gv->logconfig, "ddsi_raweth_create_conn %s port %u - using port number as ethernet type, %u won't do\n", mcast ? "multicast" : "unicast", port, port);
//        return DDS_RETCODE_ERROR;
//    }
    // TODO: It looks like raweth uses ethernet type as port number
    if(port + DPDK_L2_ETHER_TYPE >= UINT16_MAX) {
        DDS_CERROR(&fact->gv->logconfig, "ddsi_dpdk2_l2_create_conn: DDSI requested too large port number %i.", port);
        return DDS_RETCODE_ERROR;
    }

//    rc = ddsrt_socket(&sock, PF_PACKET, SOCK_DGRAM, htons((uint16_t)port));
//    if (rc != DDS_RETCODE_OK)
//    {
//        DDS_CERROR (&fact->gv->logconfig, "ddsi_raweth_create_conn %s port %u failed ... retcode = %d\n", mcast ? "multicast" : "unicast", port, rc);
//        return DDS_RETCODE_ERROR;
//    }

//    memset(&addr, 0, sizeof(addr));
//    addr.sll_family = AF_PACKET;
//    addr.sll_protocol = htons((uint16_t)port);
//    addr.sll_ifindex = (int)intf->if_index;
//    addr.sll_pkttype = PACKET_HOST | PACKET_BROADCAST | PACKET_MULTICAST;
//    rc = ddsrt_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
//    if (rc != DDS_RETCODE_OK)
//    {
//        ddsrt_close(sock);
//        DDS_CERROR (&fact->gv->logconfig, "ddsi_raweth_create_conn %s bind port %u failed ... retcode = %d\n", mcast ? "multicast" : "unicast", port, rc);
//        return DDS_RETCODE_ERROR;
//    }

    if ((uc = (ddsi_dpdk_l2_conn_t) ddsrt_malloc (sizeof (*uc))) == NULL)
    {
//        ddsrt_close(sock);
        return DDS_RETCODE_ERROR;
    }

    memset (uc, 0, sizeof (*uc));
//    uc->m_sock = sock;
//    uc->m_ifindex = addr.sll_ifindex;
    uc->m_dpdk_queue_identifier = 0;
    ddsi_factory_conn_init (fact, intf, &uc->m_base);
    uc->m_base.m_base.m_port = port;
    uc->m_base.m_base.m_trantype = DDSI_TRAN_CONN;
    uc->m_base.m_base.m_multicast = mcast;
    uc->m_base.m_base.m_handle_fn = ddsi_dpdk_l2_conn_handle;
    uc->m_base.m_locator_fn = ddsi_dpdk_l2_conn_locator;
    uc->m_base.m_read_fn = ddsi_dpdk_l2_conn_read;
    uc->m_base.m_write_fn = ddsi_dpdk_l2_conn_write;
    uc->m_base.m_disable_multiplexing_fn = 0;

    DDS_CTRACE (&fact->gv->logconfig, "ddsi_dpdk_l2_create_conn %s socket port %u\n", mcast ? "multicast" : "unicast", uc->m_base.m_base.m_port);
    *conn_out = &uc->m_base;
    printf("DPDK: Connection opened on port %i\n", port);
    return DDS_RETCODE_OK;
}

static int isbroadcast(const ddsi_locator_t *loc)
{
    // VB: This should be OK as is.
    int i;
    for(i = 0; i < 6; i++)
        if (loc->address[10 + i] != 0xff)
            return 0;
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

static int ddsi_dpdk_l2_join_mc (struct ddsi_tran_conn * conn, const ddsi_locator_t *srcloc, const ddsi_locator_t *mcloc, const struct ddsi_network_interface *interf)
{
    if (isbroadcast(mcloc))
        return 0;
    else
    {
        // VB: Multicast groups unsupported for now
        (void)conn;
        (void)srcloc;
        (void)interf;
        assert(false);
        return DDS_RETCODE_UNSUPPORTED;
//        ddsi_raweth_conn_t uc = (ddsi_raweth_conn_t) conn;
//        (void)srcloc;
//        return joinleave_asm_mcgroup(uc->m_sock, 1, mcloc, interf);
    }
}

static int ddsi_dpdk_l2_leave_mc (struct ddsi_tran_conn * conn, const ddsi_locator_t *srcloc, const ddsi_locator_t *mcloc, const struct ddsi_network_interface *interf)
{
    if (isbroadcast(mcloc))
        return 0;
    else
    {
        // VB: Multicast groups unsupported for now
        (void)conn;
        (void)srcloc;
        (void)interf;
        assert(false);
        return DDS_RETCODE_UNSUPPORTED;
//        ddsi_raweth_conn_t uc = (ddsi_raweth_conn_t) conn;
//        (void)srcloc;
//        return joinleave_asm_mcgroup(uc->m_sock, 0, mcloc, interf);
    }
}

static void ddsi_dpdk_l2_release_conn (struct ddsi_tran_conn * conn)
{
    ddsi_dpdk_l2_conn_t uc = (ddsi_dpdk_l2_conn_t) conn;
    DDS_CTRACE (&conn->m_base.gv->logconfig,
                "ddsi_dpdk_l2_release_conn %s port %d\n",
                conn->m_base.m_multicast ? "multicast" : "unicast",
                uc->m_base.m_base.m_port);
//    ddsrt_close (uc->m_sock);
    ddsrt_free (conn);
}

static int ddsi_dpdk_l2_is_loopbackaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc)
{
    (void) tran;
    (void) loc;
    return 0;
}

static int ddsi_dpdk_l2_is_mcaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc)
{
    (void) tran;
    assert (loc->kind == DDSI_LOCATOR_KIND_DPDK_L2);
    return (loc->address[10] & 1);
}

static int ddsi_dpdk_l2_is_ssm_mcaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc)
{
    (void) tran;
    (void) loc;
    return 0;
}

static enum ddsi_nearby_address_result ddsi_dpdk_l2_is_nearby_address (const ddsi_locator_t *loc, size_t ninterf, const struct ddsi_network_interface interf[], size_t *interf_idx)
{
    (void) ninterf;
    // VB: This looks up only the address of the first interface.
    // TODO: OK? Depends on if ddsi_network_interface is reliable
    if (interf_idx)
        *interf_idx = 0;
    if (memcmp (interf[0].loc.address, loc->address, sizeof (loc->address)) == 0)
        return DNAR_SELF;
    else
        return DNAR_LOCAL;
}

static enum ddsi_locator_from_string_result ddsi_dpdk_l2_address_from_string (const struct ddsi_tran_factory *tran, ddsi_locator_t *loc, const char *str)
{
    // VB: MAC Address parsing should be ok. Check if we want to set port to something
    int i = 0;
    (void)tran;
    loc->kind = DDSI_LOCATOR_KIND_DPDK_L2;
    loc->port = DDSI_LOCATOR_PORT_INVALID;
    memset (loc->address, 0, sizeof (loc->address));
    while (i < 6 && *str != 0)
    {
        unsigned o;
        int p;
        if (sscanf (str, "%x%n", &o, &p) != 1 || o > 255)
            return AFSR_INVALID;
        loc->address[10 + i++] = (unsigned char) o;
        str += p;
        if (i < 6)
        {
            if (*str != ':')
                return AFSR_INVALID;
            str++;
        }
    }
    if (*str)
        return AFSR_INVALID;
    return AFSR_OK;
}

static void ddsi_dpdk_l2_deinit(struct ddsi_tran_factory * fact)
{
    DDS_CLOG (DDS_LC_CONFIG, &fact->gv->logconfig, "dpdk l2 de-initialized\n");
    ddsrt_free (fact);
}

static int ddsi_dpdk_l2_enumerate_interfaces (struct ddsi_tran_factory * fact, enum ddsi_transport_selector transport_selector, ddsrt_ifaddrs_t **interfaces)
{
//  int afs[] = { AF_PACKET, DDSRT_AF_TERM };
    (void)fact;
    (void)transport_selector;
//  return ddsrt_getifaddrs(interface, afs);
    ddsrt_ifaddrs_t *interface = malloc(1 * sizeof(ddsrt_ifaddrs_t));
    if(!interface) {
        assert(false);
    }

    interface->next = NULL;
    interface->name = strdup("DPDK-0");
    interface->index = 0;
    interface->flags = IFF_BROADCAST | IFF_MULTICAST | IFF_UP | IFF_NOARP | IFF_PROMISC;
    interface->type = DDSRT_IFTYPE_WIRED;

    // TODO: Check whether we need an address family
    interface->addr = ddsrt_malloc(sizeof(struct sockaddr));
    interface->addr->sa_family = AF_UNSPEC;
    DDSRT_STATIC_ASSERT(sizeof(interface->addr->sa_data) == 14);
    // TODO: We assume interface zero
    struct rte_ether_addr addr = get_dpdk_interface_mac_address(0);
    copy_mac_address_and_zero(interface->addr->sa_data, 8, &addr);

    // Netmask: FF:FF ... 00:00:00:00:00
    interface->netmask = ddsrt_malloc(sizeof(struct sockaddr));
    interface->netmask->sa_family = AF_UNSPEC;
    memset(interface->netmask->sa_data, 0xFF, 8);
    memset(interface->netmask->sa_data + 8, 0, 6);

    // Broadcast address: 00:00 ... FF:FF:FF:FF:FF:FF
    interface->broadaddr = ddsrt_malloc(sizeof(struct sockaddr));
    interface->broadaddr->sa_family = AF_UNSPEC;
    memset(interface->broadaddr->sa_data, 0, 8);
    memset(interface->broadaddr->sa_data + 8, 0xFF, 6);

    *interfaces = interface;
    return DDS_RETCODE_OK;
}

static int ddsi_dpdk_l2_is_valid_port (const struct ddsi_tran_factory *fact, uint32_t port)
{
    // We use a base ethernet type DPDK_L2_ETHER_TYPE and add the port number to it.
    // The total must fit into the 16 bit ether_type field.
    (void) fact;
//    return (port >= 1 && port <= 65535);
    return port < UINT16_MAX && (uint16_t)port + DPDK_L2_ETHER_TYPE < UINT16_MAX;
}

static uint32_t ddsi_dpdk_l2_receive_buffer_size (const struct ddsi_tran_factory *fact)
{
    (void) fact;
    return 0;
}

static int ddsi_dpdk_l2_locator_from_sockaddr (const struct ddsi_tran_factory *tran, ddsi_locator_t *loc, const struct sockaddr *sockaddr)
{
    (void) tran;

    if (sockaddr->sa_family != AF_UNSPEC)
        return -1;

    loc->kind = DDSI_LOCATOR_KIND_DPDK_L2;
    loc->port = DDSI_LOCATOR_PORT_INVALID;
    DDSRT_STATIC_ASSERT(sizeof(loc->address) == sizeof(sockaddr->sa_data) + 2);
    memset (loc->address, 0, 2);
    memcpy (loc->address + 2, sockaddr->sa_data, sizeof(sockaddr->sa_data));
    return 0;
}


// Implemented with help from here: https://doc.dpdk.org/guides/sample_app_ug/skeleton.html
static inline int dpdk_port_init(uint16_t port, struct rte_mempool *rx_mbuf_pool) {
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("DPDK: Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }

    // TODO: Unsupported on old DPDK
//        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
//            port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        return retval;
    }

    struct rte_eth_rxconf rxconf = dev_info.default_rxconf;
    rxconf.offloads = port_conf.rxmode.offloads;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, (unsigned int) rte_eth_dev_socket_id(port), &rxconf, rx_mbuf_pool);
        if (retval < 0) {
            return retval;
        }
    }

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, (unsigned int) rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) {
            return retval;
        }
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Enable RX in promiscuous mode for the Ethernet device. */
//    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
//    if (retval != 0)
//        return retval;

//    retval = rte_eth_dev_set_ptypes(port, RTE_PTYPE_UNKNOWN, NULL, 0);
//    if (retval < 0) {
//        return retval;
//    }
    return 0;
}


int ddsi_dpdk_l2_init (struct ddsi_domaingv *gv)
{
    struct dpdk_transport_factory *fact = ddsrt_malloc (sizeof (*fact));
    memset (fact, 0, sizeof (*fact));
    fact->m_base.gv = gv;
    fact->m_base.m_free_fn = ddsi_dpdk_l2_deinit;
    fact->m_base.m_typename = DPDK_FACTORY_TYPE_NAME;
    fact->m_base.m_default_spdp_address = "dpdk_l2/ff:ff:ff:ff:ff:ff";
    fact->m_base.m_connless = 1;
    fact->m_base.m_enable_spdp = 1;
    fact->m_base.m_supports_fn = ddsi_dpdk_l2_supports;
    fact->m_base.m_create_conn_fn = ddsi_dpdk_l2_create_conn;
    fact->m_base.m_release_conn_fn = ddsi_dpdk_l2_release_conn;
    fact->m_base.m_join_mc_fn = ddsi_dpdk_l2_join_mc;
    fact->m_base.m_leave_mc_fn = ddsi_dpdk_l2_leave_mc;
    fact->m_base.m_is_loopbackaddr_fn = ddsi_dpdk_l2_is_loopbackaddr;
    fact->m_base.m_is_mcaddr_fn = ddsi_dpdk_l2_is_mcaddr;
    fact->m_base.m_is_ssm_mcaddr_fn = ddsi_dpdk_l2_is_ssm_mcaddr;
    fact->m_base.m_is_nearby_address_fn = ddsi_dpdk_l2_is_nearby_address;
    fact->m_base.m_locator_from_string_fn = ddsi_dpdk_l2_address_from_string;
    fact->m_base.m_locator_to_string_fn = ddsi_dpdk_l2_to_string;
    fact->m_base.m_enumerate_interfaces_fn = ddsi_dpdk_l2_enumerate_interfaces;
    fact->m_base.m_is_valid_port_fn = ddsi_dpdk_l2_is_valid_port;
    fact->m_base.m_receive_buffer_size_fn = ddsi_dpdk_l2_receive_buffer_size;
    fact->m_base.m_locator_from_sockaddr_fn = ddsi_dpdk_l2_locator_from_sockaddr;
    ddsi_factory_add (gv, (struct ddsi_tran_factory *) fact);
    GVLOG (DDS_LC_CONFIG, "dpdk_l2 initialized\n");

    // We need to initialize EAL
    // TODO: This expects argc and argv
    char *arg0 = "";
    char *pseudoArgs[] = {arg0, NULL};
    int ret = rte_eal_init(0, pseudoArgs);
    if (ret != 0) {
        DDS_CERROR(&fact->m_base.gv->logconfig, "Unable to initialize DPDK RTE_EAL");
        return DDS_RETCODE_NO_NETWORK;
    }
    printf("RTE EAL init success.\n");

    // TX buffers
    fact->m_dpdk_memory_pool_tx = rte_pktmbuf_pool_create(
            "MBUF_POOL_TX", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, (int) rte_socket_id()
            );
    if (fact->m_dpdk_memory_pool_tx == NULL) {
        DDS_CERROR(&fact->m_base.gv->logconfig, "Failed to allocate DPDK mempool.");
        return DDS_RETCODE_OUT_OF_RESOURCES;
    }
    // RX buffers
    fact->m_dpdk_memory_pool_rx = rte_pktmbuf_pool_create(
            "MBUF_POOL_RX", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, (int) rte_socket_id()
    );
    if (fact->m_dpdk_memory_pool_rx == NULL) {
        DDS_CERROR(&fact->m_base.gv->logconfig, "Failed to allocate DPDK mempool.");
        return DDS_RETCODE_OUT_OF_RESOURCES;
    }

    if (dpdk_port_init(fact->dpdk_port_identifier, fact->m_dpdk_memory_pool_rx) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", fact->dpdk_port_identifier);
    }

    return 0;
}

#else

int ddsi_raweth_init (struct ddsi_domaingv *gv) { (void) gv; return 0; }

#endif /* defined __linux */
