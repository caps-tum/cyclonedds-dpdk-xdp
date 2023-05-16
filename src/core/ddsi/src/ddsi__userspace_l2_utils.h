//
// Created by Vincent Bode on 16/05/2023.
//

#ifndef CYCLONEDDS_DDSI_USERSPACE_L2_UTILS_H
#define CYCLONEDDS_DDSI_USERSPACE_L2_UTILS_H

#include <stddef.h>
#include <dds/ddsi/ddsi_ownip.h>
#include <dds/ddsi/ddsi_locator.h>
#include <dds/ddsi/ddsi_tran.h>
#include <string.h>

typedef struct {
    unsigned char bytes[6];
} userspace_l2_mac_addr;

// Convert a locator to its string representation
char *ddsi_userspace_l2_locator_to_string (char *dst, size_t sizeof_dst, const ddsi_locator_t *loc, struct ddsi_tran_conn * conn, int with_port);

// Ethertype handling

// The ethertype encodes the port number. The first 3 bits are static for identification, the last 12 bits the port number
#define DDSI_USERSPACE_L2_ETHER_TYPE_BASE 0xA000
#define DDSI_USERSPACE_L2_ETHER_TYPE_MAX 0xBFFF

static inline uint16_t ddsi_userspace_l2_get_ethertype_for_port(uint16_t port) {
    assert(port < DDSI_USERSPACE_L2_ETHER_TYPE_MAX);
    return port + DDSI_USERSPACE_L2_ETHER_TYPE_BASE;
}

static inline uint16_t ddsi_userspace_l2_is_valid_ethertype(uint16_t ethertype) {
    return ethertype >= DDSI_USERSPACE_L2_ETHER_TYPE_BASE && ethertype <= DDSI_USERSPACE_L2_ETHER_TYPE_MAX;
}

static inline uint16_t ddsi_userspace_l2_get_port_for_ethertype(uint16_t ethertype) {
    assert(ddsi_userspace_l2_is_valid_ethertype(ethertype));
    return ethertype - DDSI_USERSPACE_L2_ETHER_TYPE_BASE;
}

static inline bool ddsi_userspace_l2_is_valid_port(unsigned int port) {
    return port < DDSI_USERSPACE_L2_ETHER_TYPE_MAX - DDSI_USERSPACE_L2_ETHER_TYPE_BASE;
}

static inline int ddsi_userspace_l2_is_valid_port_fn(const struct ddsi_tran_factory *fact, uint32_t port)
{
    (void) fact;
    return ddsi_userspace_l2_is_valid_port(port);
}

// IOV utils
static inline size_t ddsi_userspace_get_total_iov_size(size_t niov, const ddsrt_iovec_t *iov) {
    size_t total_iov_size = 0;
    for(size_t i = 0; i < niov; i++) {
        total_iov_size += iov[i].iov_len;
    }
    return total_iov_size;
}

static inline size_t ddsi_userspace_copy_iov_to_packet(size_t niov, const ddsrt_iovec_t *iov, void* dest, size_t dest_size) {
    size_t totalCopySize = ddsi_userspace_get_total_iov_size(niov, iov);
    if(totalCopySize >= dest_size) {
        return 0;
    }
    for(size_t i = 0; i < niov; i++) {
        memcpy(dest, iov[i].iov_base, iov[i].iov_len);
        dest += iov[i].iov_len;
    }
    return totalCopySize;
}

// Packet utils
static inline uint16_t ddsi_userspace_get_packet_size__(uint16_t dataSize, size_t payloadOffset) {
    if(dataSize + payloadOffset > UINT16_MAX) {
        return 0;
    }
    return dataSize + (uint16_t)payloadOffset;
}
#define DDSI_USERSPACE_GET_PACKET_SIZE(dataSize, type) ddsi_userspace_get_packet_size__(dataSize, offsetof(type, payload))

static inline uint16_t ddsi_userspace_get_payload_size__(uint16_t packetSize, size_t payloadOffset) {
    if(packetSize < payloadOffset || payloadOffset > UINT16_MAX) {
        return 0;
    }
    return (uint16_t)payloadOffset - packetSize;
}
#define DDSI_USERSPACE_GET_PAYLOAD_SIZE(packetSize, type) ddsi_userspace_get_payload_size__(packetSize, offsetof(type, payload))


// Misc functions

static inline uint32_t ddsi_userspace_l2_receive_buffer_size_fn (const struct ddsi_tran_factory *fact)
{
    (void) fact;
    return 0;
}

enum ddsi_locator_from_string_result ddsi_userspace_l2_address_from_string(const struct ddsi_tran_factory *tran, ddsi_locator_t *loc, const char *str, int32_t locatorKind);

int ddsi_userspace_l2_is_loopbackaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc);
int ddsi_userspace_l2_is_mcaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc);
int ddsi_userspace_l2_is_ssm_mcaddr (const struct ddsi_tran_factory *tran, const ddsi_locator_t *loc);
enum ddsi_nearby_address_result ddsi_userspace_l2_is_nearby_address (const ddsi_locator_t *loc, size_t ninterf, const struct ddsi_network_interface *interf, size_t *interf_idx);

int ddsi_userspace_l2_join_mc (struct ddsi_tran_conn * conn, const ddsi_locator_t *srcloc, const ddsi_locator_t *mcloc, const struct ddsi_network_interface *interf);
int ddsi_userspace_l2_leave_mc (struct ddsi_tran_conn * conn, const ddsi_locator_t *srcloc, const ddsi_locator_t *mcloc, const struct ddsi_network_interface *interf);

// MAC address handling
static inline void ddsi_userspace_copy_mac_address_and_zero__(void* dest, size_t offset, void *addr) {
    // Zeros all bytes from dest to dest + offset (exclusive), copies the MAC address to dest + offset.
    // User is responsible for ensuring that there is sufficient space.
    memset(dest, 0, offset);
    memcpy(dest + offset, addr, 6);
}
#define DDSI_USERSPACE_COPY_MAC_ADDRESS_AND_ZERO(destArray, offset, macAddr) { \
    DDSRT_STATIC_ASSERT(sizeof(destArray) == offset + sizeof(*macAddr)); \
    ddsi_userspace_copy_mac_address_and_zero__(destArray, offset, macAddr); \
}

int ddsi_userspace_create_fake_interface(ddsrt_ifaddrs_t **interfaces, userspace_l2_mac_addr *mac_addr);

#endif //CYCLONEDDS_DDSI_USERSPACE_L2_UTILS_H
