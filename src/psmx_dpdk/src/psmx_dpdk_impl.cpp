// Copyright(c) 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <assert.h>
#include <inttypes.h>
#include <string>
#include <memory>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <cstring>
#include <limits>
#include <stdexcept>

#include "dds/ddsrt/string.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/mh3.h"
#include "dds/ddsc/dds_loan.h"
#include "dds/ddsc/dds_psmx.h"

#include "psmx_dpdk_impl.hpp"

#define ERROR_PREFIX "=== [DPDK] "

#define DEFAULT_INSTANCE_NAME "CycloneDDS-DPDK-PSMX\0"
#define DEFAULT_TOPIC_NAME "CycloneDDS-DPDK-PSMX node_id discovery\0"

#ifndef RTE_ETHER_ADDR_BYTES
// Imported from DPDK 23 cause the older version does not seem to support it.
#define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
					 ((mac_addrs)->addr_bytes[1]), \
					 ((mac_addrs)->addr_bytes[2]), \
					 ((mac_addrs)->addr_bytes[3]), \
					 ((mac_addrs)->addr_bytes[4]), \
					 ((mac_addrs)->addr_bytes[5])
#endif

/*forward declarations of functions*/
namespace dpdk_psmx {

    // Some static configuration
    // From DPDK guide: https://github.com/DPDK/dpdk/blob/main/examples/skeleton/basicfwd.c
    constexpr auto NUM_MBUFS = 8191;
    constexpr auto MBUF_CACHE_SIZE = 250;
    constexpr auto BURST_SIZE = 32;
    constexpr auto RX_RING_SIZE = 1024;
    constexpr auto TX_RING_SIZE = 1024;

    // DPDK Packets
    struct dpdk_packet {
        struct rte_ether_hdr header;
        uint64_t topicId;

    };

    static bool dpdk_data_type_supported(dds_psmx_data_type_properties_t data_type);

    static bool dpdk_qos_supported(const struct dds_qos *qos);

    static struct dds_psmx_topic *
    dpdk_create_topic(struct dds_psmx *psmx, const char *topic_name, dds_psmx_data_type_properties_t data_type_props);

    static dds_return_t dpdk_delete_topic(struct dds_psmx_topic *psmx_topic);

    static dds_return_t dpdk_psmx_deinit(struct dds_psmx *self);

    static dds_psmx_node_identifier_t dpdk_psmx_get_node_id(const struct dds_psmx *psmx);


    static const dds_psmx_ops_t psmx_ops = {
            .data_type_supported = dpdk_data_type_supported,
            .qos_supported = dpdk_qos_supported,
            .create_topic = dpdk_create_topic,
            .delete_topic = dpdk_delete_topic,
            .deinit = dpdk_psmx_deinit,
            .get_node_id = dpdk_psmx_get_node_id,
    };


    static bool dpdk_serialization_required(dds_psmx_data_type_properties_t data_type);

    static struct dds_psmx_endpoint *
    dpdk_create_endpoint(struct dds_psmx_topic *psmx_topic, dds_psmx_endpoint_type_t endpoint_type);

    static dds_return_t dpdk_delete_endpoint(struct dds_psmx_endpoint *psmx_endpoint);

    static const dds_psmx_topic_ops_t psmx_topic_ops = {
            .serialization_required = dpdk_serialization_required,
            .create_endpoint = dpdk_create_endpoint,
            .delete_endpoint = dpdk_delete_endpoint,
    };


    static dds_loaned_sample_t *dpdk_req_loan(struct dds_psmx_endpoint *psmx_endpoint, uint32_t size_requested);

    static dds_return_t dpdk_write(struct dds_psmx_endpoint *psmx_endpoint, dds_loaned_sample_t *data);

    static dds_loaned_sample_t *dpdk_take(struct dds_psmx_endpoint *psmx_endpoint);

    static dds_return_t dpdk_on_data_available(struct dds_psmx_endpoint *psmx_endpoint, dds_entity_t reader);

    static const dds_psmx_endpoint_ops_t psmx_ep_ops = {
            .request_loan = dpdk_req_loan,
            .write = dpdk_write,
            .take = dpdk_take,
            .on_data_available = dpdk_on_data_available
    };


    static void dpdk_loaned_sample_free(dds_loaned_sample_t *to_fini);

    static const dds_loaned_sample_ops_t ls_ops = {
            .free = dpdk_loaned_sample_free,
            .ref = nullptr,
            .unref = nullptr,
            .reset = nullptr
    };


    struct dpdk_psmx : public dds_psmx_t {
        dpdk_psmx(dds_loan_origin_type_t identifier, const char *service_name);

        ~dpdk_psmx();

        void discover_node_id(dds_psmx_node_identifier_t fallback);

        char _service_name[64];
        //  std::unique_ptr<iox::popo::Listener> _listener;  //the listener needs to be created after iox runtime has been initialized
        dds_psmx_node_identifier_t node_id = 0;

        uint16_t dpdk_port_id = 0;
        rte_mempool *dpdk_mempool = nullptr;
        //  std::shared_ptr<iox::popo::UntypedPublisher> node_id_publisher;
    };

    // Some necessary dpdk functions
    static inline int dpdk_port_init(uint16_t port, struct rte_mempool *mbuf_pool);


    dpdk_psmx::dpdk_psmx(dds_loan_origin_type_t identifier, const char *service_name) :
            dds_psmx_t{
                    .ops = psmx_ops,
                    .instance_name = DEFAULT_INSTANCE_NAME,
                    .priority = 0,
                    .locator = nullptr,
                    .node_id = identifier,
                    .psmx_topics = nullptr
            }
    //  _listener()
    {
        if (service_name == nullptr)
            snprintf(_service_name, sizeof(_service_name), "CycloneDDS dpdk_psmx %08X",
                     identifier);  //replace with hash of _instance_name and domain id
        else
            snprintf(_service_name, sizeof(_service_name), "%s", service_name);

        char buffer[64];
        clock_t t = clock();
        uint64_t id = static_cast<uint64_t>(t) ^ ((uint64_t) this) ^ identifier;

        sprintf(buffer, "CycloneDDS-dpdk_psmx-%016" PRIx64, id);

        // TODO: This expects argc and argv
        char *pseudoArgs = "";
        int ret = rte_eal_init(0, &pseudoArgs);
        if (ret < 0) {
            throw std::runtime_error("Unable to initialize DPDK RTE_EAL");
        }

        //  iox::runtime::PoshRuntime::initRuntime(buffer);
        //  _listener = std::unique_ptr<iox::popo::Listener>(new iox::popo::Listener());

        constexpr auto num_ports_used = 1;
        dpdk_port_id = rte_eth_find_next_owned_by(0, 0);
        dpdk_mempool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * num_ports_used,
                                               MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (dpdk_port_init(dpdk_port_id, dpdk_mempool) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", dpdk_port_id);
        }

        discover_node_id(id);
        dds_psmx_init_generic(this);
    }

    dpdk_psmx::~dpdk_psmx() {
        // TODO: We probably need some cleanup here
        rte_eal_cleanup();

        if (dds_psmx_cleanup_generic(this) != DDS_RETCODE_OK) {
            fprintf(stderr, ERROR_PREFIX "error during dds_psmx_cleanup_generic\n");
            assert(false);
        }
    }

    // Implemented with help from here: https://doc.dpdk.org/guides/sample_app_ug/skeleton.html
    static inline int dpdk_port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
        struct rte_eth_conf port_conf;
        const uint16_t rx_rings = 1, tx_rings = 1;
        uint16_t nb_rxd = RX_RING_SIZE;
        uint16_t nb_txd = TX_RING_SIZE;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;

        if (!rte_eth_dev_is_valid_port(port))
            return -1;

        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
            printf("DPDK: Error during getting device (port %u) info: %s\n", port, strerror(-retval));
            return retval;
        }

        // Unsupported on old DPDK
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

        /* Allocate and set up 1 RX queue per Ethernet port. */
        for (q = 0; q < rx_rings; q++) {
            retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
            if (retval < 0) {
                return retval;
            }
        }

        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        /* Allocate and set up 1 TX queue per Ethernet port. */
        for (q = 0; q < tx_rings; q++) {
            retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
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
        retval = rte_eth_promiscuous_enable(port);
        /* End of setting RX port in promiscuous mode. */
        if (retval != 0)
            return retval;

        return 0;
    }

    void dpdk_psmx::discover_node_id(dds_psmx_node_identifier_t fallback) {

        // FIXME: fopen (/etc/machine-id), fread(fin, rb), convert to uint64_t

        /* Display the port MAC address. */
        struct rte_ether_addr addr;
        auto retval = rte_eth_macaddr_get(dpdk_port_id, &addr);
        if (retval != 0) {
            throw std::runtime_error("DPDK: Failed to determine device MAC address.");
        }

        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
               dpdk_port_id, RTE_ETHER_ADDR_BYTES(&addr));

        static_assert(sizeof(node_id) > sizeof(addr.addr_bytes), "Cannot fit DPDK device id into PSMX identifier.");
        std::memcpy(&node_id, addr.addr_bytes, sizeof(addr.addr_bytes));
    }

    struct dpdk_psmx_topic : public dds_psmx_topic_t {
        dpdk_psmx_topic(dpdk_psmx &psmx, const char *topic_name, dds_psmx_data_type_properties_t data_type_props);

        ~dpdk_psmx_topic();

        dpdk_psmx &_parent;
        char _dpdk_topic_name[64];
        char _data_type_str[64];
    };

    dpdk_psmx_topic::dpdk_psmx_topic(dpdk_psmx &psmx, const char *topic_name,
                                     dds_psmx_data_type_properties_t data_type_props) :
            dds_psmx_topic_t
                    {
                            .ops = psmx_topic_ops,
                            .psmx_instance = reinterpret_cast<struct dds_psmx *>(&psmx),
                            .topic_name = {0},
                            .data_type = 0,
                            .psmx_endpoints = nullptr,
                            .data_type_props = data_type_props
                    }, _parent(psmx) {
        dds_psmx_topic_init_generic(this, &psmx, topic_name);
        if (strlen(topic_name) <= 63) {
            strcpy(_dpdk_topic_name, topic_name);
        } else {
            strncpy(_dpdk_topic_name, topic_name, sizeof(_dpdk_topic_name) - 9);
            uint32_t topic_name_hash = ddsrt_mh3(topic_name, strlen(topic_name), 0);
            snprintf(_dpdk_topic_name + sizeof(_dpdk_topic_name) - 9, 9, "%08X", topic_name_hash);
        }

        sprintf(_data_type_str, "CycloneDDS dpdk_datatype %08X", data_type);
        if (dds_add_psmx_topic_to_list(reinterpret_cast<struct dds_psmx_topic *>(this), &psmx.psmx_topics) !=
            DDS_RETCODE_OK) {
            fprintf(stderr, ERROR_PREFIX "could not add PSMX topic to list\n");
            assert(false);
        }
    }

    dpdk_psmx_topic::~dpdk_psmx_topic() {
        if (dds_psmx_topic_cleanup_generic(reinterpret_cast<struct dds_psmx_topic *>(this)) != DDS_RETCODE_OK) {
            fprintf(stderr, ERROR_PREFIX "could not remove PSMX from list\n");
            assert(false);
        }
    }

    struct dpdk_psmx_endpoint : public dds_psmx_endpoint_t {
        dpdk_psmx_endpoint(dpdk_psmx_topic &topic, dds_psmx_endpoint_type_t endpoint_type);

        ~dpdk_psmx_endpoint();

        dpdk_psmx_topic &_parent;
        void *_dpdk_endpoint = nullptr;
        dds_entity_t cdds_endpoint;
    };

    dpdk_psmx_endpoint::dpdk_psmx_endpoint(dpdk_psmx_topic &psmx_topic, dds_psmx_endpoint_type_t endpoint_type) :
            dds_psmx_endpoint_t
                    {
                            .ops = psmx_ep_ops,
                            .psmx_topic = reinterpret_cast<struct dds_psmx_topic *>(&psmx_topic),
                            .endpoint_type = endpoint_type
                    }, _parent(psmx_topic) {
        switch (endpoint_type) {
            case DDS_PSMX_ENDPOINT_TYPE_READER:
//          _iox_endpoint = new iox::popo::UntypedSubscriber({_parent._parent._service_name, psmx_topic._dpdk_topic_name, _parent._data_type_str});
                break;
            case DDS_PSMX_ENDPOINT_TYPE_WRITER:
//          _iox_endpoint = new iox::popo::UntypedPublisher({_parent._parent._service_name, psmx_topic._dpdk_topic_name, _parent._data_type_str});
                break;
            default:
                fprintf(stderr, ERROR_PREFIX "PSMX endpoint type not accepted\n");
                assert(false);
        }

        if (dds_add_psmx_endpoint_to_list(reinterpret_cast<struct dds_psmx_endpoint *>(this),
                                          &psmx_topic.psmx_endpoints) != DDS_RETCODE_OK) {
            fprintf(stderr, ERROR_PREFIX "could not add PSMX endpoint to list\n");
            assert(false);
        }

    }

    dpdk_psmx_endpoint::~dpdk_psmx_endpoint() {
        switch (endpoint_type) {
            case DDS_PSMX_ENDPOINT_TYPE_READER:
//          {
//            auto sub = reinterpret_cast<iox::popo::UntypedSubscriber*>(_iox_endpoint);
//            this->_parent._parent._listener->detachEvent(*sub, iox::popo::SubscriberEvent::DATA_RECEIVED);
//            delete sub;
//          }
                break;
            case DDS_PSMX_ENDPOINT_TYPE_WRITER:
//          delete reinterpret_cast<iox::popo::UntypedPublisher*>(_iox_endpoint);
                break;
            default:
                fprintf(stderr, ERROR_PREFIX "PSMX endpoint type not accepted\n");
                assert(false);
        }
    }

    struct dpdk_metadata : public dds_psmx_metadata_t {
        uint32_t sample_size;
    };

    static constexpr uint32_t dpdk_padding =
            sizeof(dds_psmx_metadata_t) % 8 ? (sizeof(dds_psmx_metadata_t) / 8 + 1) * 8 : sizeof(dds_psmx_metadata_t);

    struct dpdk_loaned_sample : public dds_loaned_sample_t {
        dpdk_loaned_sample(struct dds_psmx_endpoint *origin, uint32_t sz, const void *ptr,
                           dds_loaned_sample_state_t st, rte_mbuf* mbuf_handle);

        ~dpdk_loaned_sample();
        
        rte_mbuf* mbuf_handle;
    };

    dpdk_loaned_sample::dpdk_loaned_sample(struct dds_psmx_endpoint *origin, uint32_t sz, const void *ptr,
                                           dds_loaned_sample_state_t st, rte_mbuf* mbuf_handle) :
            dds_loaned_sample_t{
                    .ops = ls_ops,
                    .loan_origin = origin,
                    .manager = nullptr,
                    .metadata = ((struct dds_psmx_metadata *) ptr),
                    .sample_ptr = ((char *) ptr) + dpdk_padding,  //alignment?
                    .loan_idx = 0,
                    .refs = {.v = 0}
            } {
        metadata->sample_state = st;
        metadata->data_type = origin->psmx_topic->data_type;
        metadata->data_origin = origin->psmx_topic->psmx_instance->node_id;
        metadata->sample_size = sz;
        metadata->block_size = sz + dpdk_padding;

        this->mbuf_handle = mbuf_handle;
    }

    dpdk_loaned_sample::~dpdk_loaned_sample() {
//        auto cpp_ep_ptr = reinterpret_cast<dpdk_psmx_endpoint *>(loan_origin);
//        if (metadata) {
//            switch (cpp_ep_ptr->endpoint_type) {
//                case DDS_PSMX_ENDPOINT_TYPE_READER:
//            reinterpret_cast<iox::popo::UntypedSubscriber*>(cpp_ep_ptr->_iox_endpoint)->release(metadata);
//                    break;
//                case DDS_PSMX_ENDPOINT_TYPE_WRITER:
//            reinterpret_cast<iox::popo::UntypedPublisher*>(cpp_ep_ptr->_iox_endpoint)->release(metadata);
//                    break;
//                default:
//                    fprintf(stderr, ERROR_PREFIX "PSMX endpoint type not accepted\n");
//                    assert(false);
//            }
//        }
        if(mbuf_handle != nullptr) {
            rte_pktmbuf_free(mbuf_handle);
        }
    }


    // dds_psmx_ops_t implementation

    static bool dpdk_data_type_supported(dds_psmx_data_type_properties_t data_type) {
        return !DDS_DATA_TYPE_CONTAINS_INDIRECTIONS (data_type);
    }

    static bool dpdk_qos_supported(const struct dds_qos *qos) {
        dds_history_kind h_kind;
        if (dds_qget_history(qos, &h_kind, NULL) && h_kind != DDS_HISTORY_KEEP_LAST)
            return false;

        dds_durability_kind_t d_kind;
        if (dds_qget_durability(qos, &d_kind) &&
            !(d_kind == DDS_DURABILITY_VOLATILE || d_kind == DDS_DURABILITY_TRANSIENT_LOCAL))
            return false;

        // FIXME: add more QoS checks (durability_service.kind/depth, ignore_local, partition, liveliness, deadline)

        return true;
    }

    static struct dds_psmx_topic *
    dpdk_create_topic(struct dds_psmx *psmx, const char *topic_name, dds_psmx_data_type_properties_t data_type_props) {
        assert(psmx);
        auto cpp_psmx_ptr = reinterpret_cast<dpdk_psmx *>(psmx);
        return reinterpret_cast<struct dds_psmx_topic *>(new dpdk_psmx_topic(*cpp_psmx_ptr, topic_name,
                                                                             data_type_props));
    }

    static dds_return_t dpdk_delete_topic(struct dds_psmx_topic *psmx_topic) {
        assert(psmx_topic);
        delete reinterpret_cast<dpdk_psmx_topic *>(psmx_topic);
        return DDS_RETCODE_OK;
    }

    static dds_return_t dpdk_psmx_deinit(struct dds_psmx *psmx) {
        assert(psmx);
        delete reinterpret_cast<dpdk_psmx *>(psmx);
        return DDS_RETCODE_OK;
    }

    static dds_psmx_node_identifier_t dpdk_psmx_get_node_id(const struct dds_psmx *psmx) {
        return reinterpret_cast<const dpdk_psmx *>(psmx)->node_id;
    }


    // dds_psmx_topic_ops_t implementation

    static bool dpdk_serialization_required(dds_psmx_data_type_properties_t data_type) {
        return (data_type & DDS_DATA_TYPE_IS_FIXED_SIZE) == 0 && DDS_DATA_TYPE_CONTAINS_INDIRECTIONS(data_type) == 0;
    }

    static struct dds_psmx_endpoint *
    dpdk_create_endpoint(struct dds_psmx_topic *psmx_topic, dds_psmx_endpoint_type_t endpoint_type) {
        assert(psmx_topic);
        auto cpp_topic_ptr = reinterpret_cast<dpdk_psmx_topic *>(psmx_topic);
        return reinterpret_cast<struct dds_psmx_endpoint *>(new dpdk_psmx_endpoint(*cpp_topic_ptr, endpoint_type));
    }

    static dds_return_t dpdk_delete_endpoint(struct dds_psmx_endpoint *psmx_endpoint) {
        assert(psmx_endpoint);
        delete reinterpret_cast<dpdk_psmx_endpoint *>(psmx_endpoint);
        return DDS_RETCODE_OK;
    }

    // dds_psmx_endpoint_ops_t implementation

    static dds_loaned_sample_t *dpdk_req_loan(struct dds_psmx_endpoint *psmx_endpoint, uint32_t size_requested) {
        auto cpp_ep_ptr = reinterpret_cast<dpdk_psmx_endpoint *>(psmx_endpoint);
        dds_loaned_sample_t *result_ptr = nullptr;
        if (psmx_endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_WRITER) {
//            // TODO: Here we need to allocate packets
//            result_ptr = static_cast<dds_loaned_sample_t *>(std::malloc(size_requested + dpdk_padding));
//            if (result_ptr == nullptr) {
//                throw std::runtime_error("Failed to allocate memory for sample");
//            }

            auto *mbuf = rte_pktmbuf_alloc(
                    static_cast<dpdk_psmx *>(cpp_ep_ptr->psmx_topic->psmx_instance)->dpdk_mempool
            );
            auto *data_buffer = rte_pktmbuf_append(mbuf, static_cast<uint16_t>(size_requested));
            if (data_buffer == nullptr) {
                throw std::runtime_error("Failed to allocate memory in packet.");
            }
            auto *loan = new dpdk_loaned_sample(
                    psmx_endpoint, size_requested, data_buffer, DDS_LOANED_SAMPLE_STATE_UNITIALIZED, mbuf
            );
            result_ptr = static_cast<dds_loaned_sample_t *>(loan);
//        auto ptr = reinterpret_cast<iox::popo::UntypedPublisher*>(cpp_ep_ptr->_iox_endpoint);
//        ptr->loan(size_requested + iox_padding)
//          .and_then([&](const void* sample_ptr) {
//            result_ptr = reinterpret_cast<dds_loaned_sample_t*>(new iox_loaned_sample(psmx_endpoint, size_requested, sample_ptr, DDS_LOANED_SAMPLE_STATE_UNITIALIZED));
//          })
//          .or_else([&](auto& error) {
//            fprintf(stderr, ERROR_PREFIX "failure getting loan: %s\n", iox::popo::asStringLiteral(error));
//          });
        }

        return result_ptr;
    }

    static dds_return_t dpdk_write(struct dds_psmx_endpoint *psmx_endpoint, dds_loaned_sample_t *data) {
        assert(psmx_endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_WRITER);
//        auto endpoint_ptr = static_cast<dpdk_psmx_endpoint *>(psmx_endpoint);
        auto *dpdk_psmx_instance = static_cast<dpdk_psmx *>(psmx_endpoint->psmx_topic->psmx_instance);


        const uint16_t number_transmitted = rte_eth_tx_burst(
                dpdk_psmx_instance->dpdk_port_id,
                0, // Queue id
                &static_cast<dpdk_loaned_sample*>(data)->mbuf_handle,
                1
        );

        if(number_transmitted != 1) {
            throw std::runtime_error("Failed to transmit DPDK packet");
        }

//        auto publisher = reinterpret_cast<iox::popo::UntypedPublisher *>(endpoint_ptr->_iox_endpoint);
//
//        publisher->publish(data->metadata);

        
        data->metadata = NULL;
        data->sample_ptr = NULL;

        return DDS_RETCODE_OK;
    }

    static dds_loaned_sample_t *incoming_sample_to_loan(dpdk_psmx_endpoint *psmx_endpoint, const void *sample, rte_mbuf* mbuf_handle) {
        auto md = reinterpret_cast<const dds_psmx_metadata_t *>(sample);
        return new dpdk_loaned_sample(psmx_endpoint, md->sample_size, sample, md->sample_state, mbuf_handle);
    }

    static dds_loaned_sample_t *dpdk_take(struct dds_psmx_endpoint *psmx_endpoint) {
        assert(psmx_endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_READER);
        auto endpoint_ptr = reinterpret_cast<dpdk_psmx_endpoint *>(psmx_endpoint);
        auto *dpdk_psmx_instance = static_cast<dpdk_psmx *>(endpoint_ptr->psmx_topic->psmx_instance);

        // We only want to receive a single packet here.
        auto *mbuf = rte_pktmbuf_alloc(dpdk_psmx_instance->dpdk_mempool);
        const uint16_t number_received = rte_eth_rx_burst(
                dpdk_psmx_instance->dpdk_port_id,
                0,
                &mbuf,
                1
        );
        if (number_received != 1) {
            throw std::runtime_error("Error: Number of received packets was unexpected.");
        }
//        auto subscriber = reinterpret_cast<iox::popo::UntypedSubscriber *>(endpoint_ptr->_iox_endpoint);
//        assert(subscriber);
//        dds_loaned_sample_t *ptr = nullptr;
//        subscriber->take()
//                .and_then([&](const void *sample) {
//                    ptr = incoming_sample_to_loan(endpoint_ptr, sample);
//                });
        return incoming_sample_to_loan(endpoint_ptr, rte_pktmbuf_mtod(mbuf, void*), mbuf);
    }

//    static void on_incoming_data_callback(iox::popo::UntypedSubscriber *subscriber, dpdk_psmx_endpoint *psmx_endpoint) {
//        while (subscriber->hasData()) {
//            subscriber->take().and_then([&](auto &sample) {
//                auto data = incoming_sample_to_loan(psmx_endpoint, sample);
//                (void) dds_reader_store_loaned_sample(psmx_endpoint->cdds_endpoint, data);
//            });
//        }
//    }

    static uint16_t on_incoming_data_callback(
            uint16_t port_number __rte_unused, uint16_t queue_index __rte_unused,
            struct rte_mbuf **packets, uint16_t number_packets,
            uint16_t max_packets __rte_unused, void *user_data __rte_unused) {
        auto *psmx_endpoint = static_cast<dpdk_psmx_endpoint *>(user_data);
        for (int packet_id = 0; packet_id < number_packets; packet_id++) {
            auto *packet = packets[packet_id];
            incoming_sample_to_loan(psmx_endpoint, packet->buf_addr, packet);
        }
        return number_packets;
    }


    static dds_return_t dpdk_on_data_available(struct dds_psmx_endpoint *psmx_endpoint, dds_entity_t reader) {
        auto endpoint = reinterpret_cast<dpdk_psmx_endpoint *>(psmx_endpoint);
        assert(endpoint && endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_READER);

        endpoint->cdds_endpoint = reader;

        auto register_return_code = rte_eth_add_rx_callback(
                reinterpret_cast<dpdk_psmx *>(endpoint->psmx_topic->psmx_instance)->dpdk_port_id,
                0,
                on_incoming_data_callback,
                static_cast<void *>(endpoint)
        );
        if (register_return_code == NULL) {
            return DDS_RETCODE_ERROR;
        }
//        auto iox_subscriber = reinterpret_cast<iox::popo::UntypedSubscriber *>(endpoint->_iox_endpoint);
//        endpoint->_parent._parent._listener->attachEvent(
//                        *iox_subscriber,
//                        iox::popo::SubscriberEvent::DATA_RECEIVED,
//                        iox::popo::createNotificationCallback(on_incoming_data_callback, *endpoint))
//                .and_then([&]() { returnval = DDS_RETCODE_OK; })
//                .or_else([&](auto) { std::cerr << "failed to attach subscriber\n"; });

        return DDS_RETCODE_OK;
    }


    // dds_loaned_sample_ops_t implementation

    static void dpdk_loaned_sample_free(dds_loaned_sample_t *loan) {
        assert(loan);
        delete reinterpret_cast<dpdk_loaned_sample *>(loan);
    }


};  //namespace iox_psmx


static char *get_config_option_value(const char *conf, const char *option_name) {
    char *copy = dds_string_dup(conf), *cursor = copy, *tok;
    while ((tok = ddsrt_strsep(&cursor, ",/|;")) != nullptr) {
        if (strlen(tok) == 0)
            continue;
        char *name = ddsrt_strsep(&tok, "=");
        if (name == nullptr || tok == nullptr) {
            dds_free(copy);
            return nullptr;
        }
        if (strcmp(name, option_name) == 0) {
            char *ret = dds_string_dup(tok);
            dds_free(copy);
            return ret;
        }
    }
    dds_free(copy);
    return nullptr;
}

//static iox::log::LogLevel toLogLevel(const char *level_str) {
//    if (strcmp(level_str, "OFF") == 0) return iox::log::LogLevel::kOff;
//    if (strcmp(level_str, "FATAL") == 0) return iox::log::LogLevel::kFatal;
//    if (strcmp(level_str, "ERROR") == 0) return iox::log::LogLevel::kError;
//    if (strcmp(level_str, "WARN") == 0) return iox::log::LogLevel::kWarn;
//    if (strcmp(level_str, "INFO") == 0) return iox::log::LogLevel::kInfo;
//    if (strcmp(level_str, "DEBUG") == 0) return iox::log::LogLevel::kDebug;
//    if (strcmp(level_str, "VERBOSE") == 0) return iox::log::LogLevel::kVerbose;
//    return iox::log::LogLevel::kOff;
//}

dds_return_t dpdk_create_psmx(struct dds_psmx **psmx, dds_loan_origin_type_t identifier, const char *config) {
    assert(psmx);

    char *service_name = get_config_option_value(config, "SERVICE_NAME");
//    char *log_level = get_config_option_value(config, "LOG_LEVEL");
//    if (log_level != nullptr) {
//        iox::log::LogManager::GetLogManager().SetDefaultLogLevel(toLogLevel(log_level),
//                                                                 iox::log::LogLevelOutput::kHideLogLevel);
//    }

    auto ptr = new dpdk_psmx::dpdk_psmx(identifier, service_name);

    if (service_name)
        dds_free(service_name);
//    if (log_level)
//        dds_free(log_level);

    if (ptr == nullptr)
        return DDS_RETCODE_ERROR;

    *psmx = reinterpret_cast<struct dds_psmx *>(ptr);
    return DDS_RETCODE_OK;
}
