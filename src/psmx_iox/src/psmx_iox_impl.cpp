//// Copyright(c) 2023 ZettaScale Technology and others
////
//// This program and the accompanying materials are made available under the
//// terms of the Eclipse Public License v. 2.0 which is available at
//// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
//// v. 1.0 which is available at
//// http://www.eclipse.org/org/documents/edl-v10.php.
////
//// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
//
//#include <assert.h>
//#include <inttypes.h>
//#include <string>
//#include <memory>
//
//#include "dds/ddsrt/string.h"
//#include "dds/ddsrt/heap.h"
//#include "dds/ddsrt/mh3.h"
//#include "dds/ddsc/dds_loan.h"
//#include "dds/ddsc/dds_psmx.h"
//
//#include "iceoryx_hoofs/posix_wrapper/signal_watcher.hpp"
//#include "iceoryx_posh/popo/untyped_publisher.hpp"
//#include "iceoryx_posh/popo/untyped_subscriber.hpp"
//#include "iceoryx_posh/popo/listener.hpp"
//#include "iceoryx_posh/runtime/posh_runtime.hpp"
//#include "iceoryx_posh/runtime/service_discovery.hpp"
//
//#include "psmx_iox_impl.hpp"
//
//#define ERROR_PREFIX "=== [ICEORYX] "
//
//#define DEFAULT_INSTANCE_NAME "CycloneDDS-IOX-PSMX\0"
//#define DEFAULT_TOPIC_NAME "CycloneDDS-IOX-PSMX node_id discovery\0"
//
//
///*forward declarations of functions*/
//namespace iox_psmx
//{
//
//static bool iox_data_type_supported (dds_psmx_data_type_properties_t data_type);
//static bool iox_qos_supported (const struct dds_qos * qos);
//static struct dds_psmx_topic* iox_create_topic (struct dds_psmx * psmx, const char * topic_name, dds_psmx_data_type_properties_t data_type_props);
//static dds_return_t iox_delete_topic (struct dds_psmx_topic *psmx_topic);
//static dds_return_t iox_psmx_deinit (struct dds_psmx * self);
//static dds_psmx_node_identifier_t iox_psmx_get_node_id (const struct dds_psmx * psmx);
//
//
//static const dds_psmx_ops_t psmx_ops = {
//  .data_type_supported = iox_data_type_supported,
//  .qos_supported = iox_qos_supported,
//  .create_topic = iox_create_topic,
//  .delete_topic = iox_delete_topic,
//  .deinit = iox_psmx_deinit,
//  .get_node_id = iox_psmx_get_node_id
//};
//
//
//static bool iox_serialization_required (dds_psmx_data_type_properties_t data_type);
//static struct dds_psmx_endpoint * iox_create_endpoint (struct dds_psmx_topic * psmx_topic, dds_psmx_endpoint_type_t endpoint_type);
//static dds_return_t iox_delete_endpoint (struct dds_psmx_endpoint * psmx_endpoint);
//
//static const dds_psmx_topic_ops_t psmx_topic_ops = {
//  .serialization_required = iox_serialization_required,
//  .create_endpoint = iox_create_endpoint,
//  .delete_endpoint = iox_delete_endpoint
//};
//
//
//static dds_loaned_sample_t * iox_req_loan (struct dds_psmx_endpoint *psmx_endpoint, uint32_t size_requested);
//static dds_return_t iox_write (struct dds_psmx_endpoint * psmx_endpoint, dds_loaned_sample_t * data);
//static dds_loaned_sample_t * iox_take (struct dds_psmx_endpoint * psmx_endpoint);
//static dds_return_t iox_on_data_available (struct dds_psmx_endpoint * psmx_endpoint, dds_entity_t reader);
//
//static const dds_psmx_endpoint_ops_t psmx_ep_ops = {
//  .request_loan = iox_req_loan,
//  .write = iox_write,
//  .take = iox_take,
//  .on_data_available = iox_on_data_available
//};
//
//
//static void iox_loaned_sample_free (dds_loaned_sample_t *to_fini);
//
//static const dds_loaned_sample_ops_t ls_ops = {
//  .free = iox_loaned_sample_free,
//  .ref = nullptr,
//  .unref = nullptr,
//  .reset = nullptr
//};
//
//
//struct iox_psmx: public dds_psmx_t
//{
//  iox_psmx(dds_loan_origin_type_t identifier, const char *service_name);
//  ~iox_psmx();
//  void discover_node_id(dds_psmx_node_identifier_t fallback);
//  char _service_name[64];
//  std::unique_ptr<iox::popo::Listener> _listener;  //the listener needs to be created after iox runtime has been initialized
//  dds_psmx_node_identifier_t node_id = 0;
//  std::shared_ptr<iox::popo::UntypedPublisher> node_id_publisher;
//};
//
//iox_psmx::iox_psmx(dds_loan_origin_type_t identifier, const char *service_name):
//  dds_psmx_t {
//    .ops = psmx_ops,
//    .instance_name = DEFAULT_INSTANCE_NAME,
//    .priority = 0,
//    .locator = nullptr,
//    .node_id = identifier,
//    .psmx_topics = nullptr
//  },
//  _listener()
//{
//  if (service_name == nullptr)
//    snprintf(_service_name, sizeof (_service_name), "CycloneDDS iox_psmx %08X", identifier);  //replace with hash of _instance_name and domain id
//  else
//    snprintf(_service_name, sizeof (_service_name), "%s", service_name);
//
//  char buffer[64];
//  clock_t t = clock();
//  uint64_t id = static_cast<uint64_t>(t) ^ ((uint64_t)this) ^ identifier;
//
//  sprintf(buffer, "CycloneDDS-iox_psmx-%016" PRIx64, id);
//  iox::runtime::PoshRuntime::initRuntime(buffer);
//  _listener = std::unique_ptr<iox::popo::Listener>(new iox::popo::Listener());
//
//  discover_node_id(id);
//  dds_psmx_init_generic(this);
//}
//
//iox_psmx::~iox_psmx()
//{
//  if (dds_psmx_cleanup_generic(this) != DDS_RETCODE_OK)
//  {
//    fprintf(stderr, ERROR_PREFIX "error during dds_psmx_cleanup_generic\n");
//    assert(false);
//  }
//}
//
//void iox_psmx::discover_node_id(dds_psmx_node_identifier_t fallback)
//{
//
//  // FIXME: fopen (/etc/machine-id), fread(fin, rb), convert to uint64_t
//
//  iox::runtime::ServiceDiscovery serviceDiscovery;
//  char tentative_node_id_str[64];
//  sprintf(tentative_node_id_str, "%016" PRIx64, fallback);
//  unsigned int node_ids_present = 0;
//  iox::capro::IdString_t outstr;
//  serviceDiscovery.findService(iox::capro::IdString_t{_service_name},
//                               iox::capro::IdString_t{DEFAULT_TOPIC_NAME},
//                               iox::capro::Wildcard,
//                               [&node_ids_present, &outstr](const iox::capro::ServiceDescription& s)
//                               {
//                                 node_ids_present++;
//                                 outstr = s.getEventIDString();
//                               },
//                               iox::popo::MessagingPattern::PUB_SUB);
//
//  if (node_ids_present > 1)
//  {
//    fprintf(stderr, ERROR_PREFIX "inconsistency during node id creation\n");
//    assert(false);
//  }
//  else if (node_ids_present == 1)
//  {
//    node_id = std::stoull(outstr, 0, 16);
//  }
//  else
//  {
//    node_id = fallback;
//    node_id_publisher = std::shared_ptr<iox::popo::UntypedPublisher>(new iox::popo::UntypedPublisher({_service_name, DEFAULT_TOPIC_NAME, tentative_node_id_str}));
//  }
//}
//
//struct iox_psmx_topic: public dds_psmx_topic_t
//{
//  iox_psmx_topic(iox_psmx &psmx, const char * topic_name, dds_psmx_data_type_properties_t data_type_props);
//  ~iox_psmx_topic();
//  iox_psmx &_parent;
//  char _iox_topic_name[64];
//  char _data_type_str[64];
//};
//
//iox_psmx_topic::iox_psmx_topic(iox_psmx &psmx, const char * topic_name, dds_psmx_data_type_properties_t data_type_props) :
//  dds_psmx_topic_t
//  {
//    .ops = psmx_topic_ops,
//    .psmx_instance = reinterpret_cast<struct dds_psmx*>(&psmx),
//    .topic_name = { 0 },
//    .data_type = 0,
//    .psmx_endpoints = nullptr,
//    .data_type_props = data_type_props
//  }, _parent(psmx)
//{
//  dds_psmx_topic_init_generic(this, &psmx, topic_name);
//  if (strlen(topic_name) <= 63)
//  {
//    strcpy(_iox_topic_name, topic_name);
//  }
//  else
//  {
//    strncpy(_iox_topic_name, topic_name, sizeof(_iox_topic_name) - 9);
//    uint32_t topic_name_hash = ddsrt_mh3(topic_name, strlen (topic_name), 0);
//    snprintf(_iox_topic_name + sizeof(_iox_topic_name) - 9, 9, "%08X", topic_name_hash);
//  }
//
//  sprintf(_data_type_str, "CycloneDDS iox_datatype %08X", data_type);
//  if (dds_add_psmx_topic_to_list(reinterpret_cast<struct dds_psmx_topic*>(this), &psmx.psmx_topics) != DDS_RETCODE_OK)
//  {
//    fprintf(stderr, ERROR_PREFIX "could not add PSMX topic to list\n");
//    assert(false);
//  }
//}
//
//iox_psmx_topic::~iox_psmx_topic()
//{
//  if (dds_psmx_topic_cleanup_generic(reinterpret_cast<struct dds_psmx_topic*>(this)) != DDS_RETCODE_OK)
//  {
//    fprintf(stderr, ERROR_PREFIX "could not remove PSMX from list\n");
//    assert(false);
//  }
//}
//
//struct iox_psmx_endpoint: public dds_psmx_endpoint_t
//{
//  iox_psmx_endpoint(iox_psmx_topic &topic, dds_psmx_endpoint_type_t endpoint_type);
//  ~iox_psmx_endpoint();
//  iox_psmx_topic &_parent;
//  void *_iox_endpoint = nullptr;
//  dds_entity_t cdds_endpoint;
//};
//
//iox_psmx_endpoint::iox_psmx_endpoint(iox_psmx_topic &psmx_topic, dds_psmx_endpoint_type_t endpoint_type):
//  dds_psmx_endpoint_t
//  {
//    .ops = psmx_ep_ops,
//    .psmx_topic = reinterpret_cast<struct dds_psmx_topic*>(&psmx_topic),
//    .endpoint_type = endpoint_type
//  }, _parent(psmx_topic)
//{
//  switch (endpoint_type)
//  {
//    case DDS_PSMX_ENDPOINT_TYPE_READER:
//      _iox_endpoint = new iox::popo::UntypedSubscriber({_parent._parent._service_name, psmx_topic._iox_topic_name, _parent._data_type_str});
//      break;
//    case DDS_PSMX_ENDPOINT_TYPE_WRITER:
//      _iox_endpoint = new iox::popo::UntypedPublisher({_parent._parent._service_name, psmx_topic._iox_topic_name, _parent._data_type_str});
//      break;
//    default:
//      fprintf(stderr, ERROR_PREFIX "PSMX endpoint type not accepted\n");
//      assert(false);
//  }
//
//  if (dds_add_psmx_endpoint_to_list(reinterpret_cast<struct dds_psmx_endpoint*>(this), &psmx_topic.psmx_endpoints) != DDS_RETCODE_OK)
//  {
//    fprintf(stderr, ERROR_PREFIX "could not add PSMX endpoint to list\n");
//    assert(false);
//  }
//
//}
//
//iox_psmx_endpoint::~iox_psmx_endpoint()
//{
//  switch (endpoint_type)
//  {
//    case DDS_PSMX_ENDPOINT_TYPE_READER:
//      {
//        auto sub = reinterpret_cast<iox::popo::UntypedSubscriber*>(_iox_endpoint);
//        this->_parent._parent._listener->detachEvent(*sub, iox::popo::SubscriberEvent::DATA_RECEIVED);
//        delete sub;
//      }
//      break;
//    case DDS_PSMX_ENDPOINT_TYPE_WRITER:
//      delete reinterpret_cast<iox::popo::UntypedPublisher*>(_iox_endpoint);
//      break;
//    default:
//      fprintf(stderr, ERROR_PREFIX "PSMX endpoint type not accepted\n");
//      assert(false);
//  }
//}
//
//struct iox_metadata: public dds_psmx_metadata_t
//{
//  uint32_t sample_size;
//};
//
//static constexpr uint32_t iox_padding = sizeof(dds_psmx_metadata_t) % 8 ? (sizeof(dds_psmx_metadata_t) / 8 + 1 ) * 8 : sizeof(dds_psmx_metadata_t);
//
//struct iox_loaned_sample: public dds_loaned_sample_t
//{
//  iox_loaned_sample(struct dds_psmx_endpoint *origin, uint32_t sz, const void * ptr, dds_loaned_sample_state_t st);
//  ~iox_loaned_sample();
//};
//
//iox_loaned_sample::iox_loaned_sample(struct dds_psmx_endpoint *origin, uint32_t sz, const void * ptr, dds_loaned_sample_state_t st):
//  dds_loaned_sample_t {
//    .ops = ls_ops,
//    .loan_origin = origin,
//    .manager = nullptr,
//    .metadata = ((struct dds_psmx_metadata *) ptr),
//    .sample_ptr = ((char*) ptr) + iox_padding,  //alignment?
//    .loan_idx = 0,
//    .refs = { .v = 0 }
//  }
//{
//  metadata->sample_state = st;
//  metadata->data_type = origin->psmx_topic->data_type;
//  metadata->data_origin = origin->psmx_topic->psmx_instance->node_id;
//  metadata->sample_size = sz;
//  metadata->block_size = sz + iox_padding;
//}
//
//iox_loaned_sample::~iox_loaned_sample()
//{
//  auto cpp_ep_ptr = reinterpret_cast<iox_psmx_endpoint*>(loan_origin);
//  if (metadata)
//  {
//    switch (cpp_ep_ptr->endpoint_type)
//    {
//      case DDS_PSMX_ENDPOINT_TYPE_READER:
//        reinterpret_cast<iox::popo::UntypedSubscriber*>(cpp_ep_ptr->_iox_endpoint)->release(metadata);
//        break;
//      case DDS_PSMX_ENDPOINT_TYPE_WRITER:
//        reinterpret_cast<iox::popo::UntypedPublisher*>(cpp_ep_ptr->_iox_endpoint)->release(metadata);
//        break;
//      default:
//        fprintf(stderr, ERROR_PREFIX "PSMX endpoint type not accepted\n");
//        assert(false);
//    }
//  }
//}
//
//
//// dds_psmx_ops_t implementation
//
//static bool iox_data_type_supported (dds_psmx_data_type_properties_t data_type)
//{
//  return !DDS_DATA_TYPE_CONTAINS_INDIRECTIONS (data_type);
//}
//
//static bool iox_qos_supported (const struct dds_qos * qos)
//{
//  dds_history_kind h_kind;
//  if (dds_qget_history (qos, &h_kind, NULL) && h_kind != DDS_HISTORY_KEEP_LAST)
//    return false;
//
//  dds_durability_kind_t d_kind;
//  if (dds_qget_durability (qos, &d_kind) && !(d_kind == DDS_DURABILITY_VOLATILE || d_kind == DDS_DURABILITY_TRANSIENT_LOCAL))
//    return false;
//
//  // FIXME: add more QoS chekcs (durability_service.kind/depth, ignore_local, partition, liveliness, deadline)
//
//  return true;
//}
//
//static struct dds_psmx_topic* iox_create_topic (struct dds_psmx * psmx, const char *topic_name, dds_psmx_data_type_properties_t data_type_props)
//{
//  assert(psmx);
//  auto cpp_psmx_ptr = reinterpret_cast<iox_psmx*>(psmx);
//  return reinterpret_cast<struct dds_psmx_topic*>(new iox_psmx_topic(*cpp_psmx_ptr, topic_name, data_type_props));
//}
//
//static dds_return_t iox_delete_topic (struct dds_psmx_topic *psmx_topic)
//{
//  assert(psmx_topic);
//  delete reinterpret_cast<iox_psmx_topic*>(psmx_topic);
//  return DDS_RETCODE_OK;
//}
//
//static dds_return_t iox_psmx_deinit (struct dds_psmx * psmx)
//{
//  assert(psmx);
//  delete reinterpret_cast<iox_psmx*>(psmx);
//  return DDS_RETCODE_OK;
//}
//
//static dds_psmx_node_identifier_t iox_psmx_get_node_id (const struct dds_psmx * psmx)
//{
//  return reinterpret_cast<const iox_psmx*>(psmx)->node_id;
//}
//
//
//// dds_psmx_topic_ops_t implementation
//
//static bool iox_serialization_required (dds_psmx_data_type_properties_t data_type)
//{
//  return (data_type & DDS_DATA_TYPE_IS_FIXED_SIZE) == 0 && DDS_DATA_TYPE_CONTAINS_INDIRECTIONS(data_type) == 0;
//}
//
//static struct dds_psmx_endpoint* iox_create_endpoint (struct dds_psmx_topic * psmx_topic, dds_psmx_endpoint_type_t endpoint_type)
//{
//  assert(psmx_topic);
//  auto cpp_topic_ptr = reinterpret_cast<iox_psmx_topic*>(psmx_topic);
//  return reinterpret_cast<struct dds_psmx_endpoint*>(new iox_psmx_endpoint(*cpp_topic_ptr, endpoint_type));
//}
//
//static dds_return_t iox_delete_endpoint (struct dds_psmx_endpoint * psmx_endpoint)
//{
//  assert(psmx_endpoint);
//  delete reinterpret_cast<iox_psmx_endpoint*>(psmx_endpoint);
//  return DDS_RETCODE_OK;
//}
//
//// dds_psmx_endpoint_ops_t implementation
//
//static dds_loaned_sample_t* iox_req_loan (struct dds_psmx_endpoint *psmx_endpoint, uint32_t size_requested)
//{
//  auto cpp_ep_ptr = reinterpret_cast<iox_psmx_endpoint*>(psmx_endpoint);
//  dds_loaned_sample_t *result_ptr = nullptr;
//  if (psmx_endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_WRITER)
//  {
//    auto ptr = reinterpret_cast<iox::popo::UntypedPublisher*>(cpp_ep_ptr->_iox_endpoint);
//    ptr->loan(size_requested + iox_padding)
//      .and_then([&](const void* sample_ptr) {
//        result_ptr = reinterpret_cast<dds_loaned_sample_t*>(new iox_loaned_sample(psmx_endpoint, size_requested, sample_ptr, DDS_LOANED_SAMPLE_STATE_UNITIALIZED));
//      })
//      .or_else([&](auto& error) {
//        fprintf(stderr, ERROR_PREFIX "failure getting loan: %s\n", iox::popo::asStringLiteral(error));
//      });
//  }
//
//  return result_ptr;
//}
//
//static dds_return_t iox_write (struct dds_psmx_endpoint * psmx_endpoint, dds_loaned_sample_t * data)
//{
//  assert(psmx_endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_WRITER);
//  auto cpp_ep_ptr = reinterpret_cast<iox_psmx_endpoint*>(psmx_endpoint);
//  auto publisher = reinterpret_cast<iox::popo::UntypedPublisher*>(cpp_ep_ptr->_iox_endpoint);
//
//  publisher->publish(data->metadata);
//  data->metadata = NULL;
//  data->sample_ptr = NULL;
//
//  return DDS_RETCODE_OK;
//}
//
//static dds_loaned_sample_t * incoming_sample_to_loan(iox_psmx_endpoint *psmx_endpoint, const void *sample)
//{
//  auto md = reinterpret_cast<const dds_psmx_metadata_t*>(sample);
//  return new iox_loaned_sample(psmx_endpoint, md->sample_size, sample, md->sample_state);
//}
//
//static dds_loaned_sample_t * iox_take (struct dds_psmx_endpoint * psmx_endpoint)
//{
//  assert(psmx_endpoint->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_READER);
//  auto cpp_ep_ptr = reinterpret_cast<iox_psmx_endpoint*>(psmx_endpoint);
//
//  auto subscriber = reinterpret_cast<iox::popo::UntypedSubscriber*>(cpp_ep_ptr->_iox_endpoint);
//  assert(subscriber);
//  dds_loaned_sample_t *ptr = nullptr;
//  subscriber->take()
//    .and_then([&](const void * sample) {
//      ptr = incoming_sample_to_loan(cpp_ep_ptr, sample);
//    });
//  return ptr;
//}
//
//static void on_incoming_data_callback(iox::popo::UntypedSubscriber * subscriber, iox_psmx_endpoint * psmx_endpoint)
//{
//  while (subscriber->hasData())
//  {
//    subscriber->take().and_then([&](auto& sample)
//    {
//      auto data = incoming_sample_to_loan(psmx_endpoint, sample);
//      (void) dds_reader_store_loaned_sample (psmx_endpoint->cdds_endpoint, data);
//    });
//  }
//}
//
//static dds_return_t iox_on_data_available (struct dds_psmx_endpoint * psmx_endpoint, dds_entity_t reader)
//{
//  auto cpp_ep_ptr = reinterpret_cast<iox_psmx_endpoint*>(psmx_endpoint);
//  assert(cpp_ep_ptr && cpp_ep_ptr->endpoint_type == DDS_PSMX_ENDPOINT_TYPE_READER);
//
//  cpp_ep_ptr->cdds_endpoint = reader;
//  auto iox_subscriber = reinterpret_cast<iox::popo::UntypedSubscriber*>(cpp_ep_ptr->_iox_endpoint);
//
//  dds_return_t returnval = DDS_RETCODE_ERROR;
//  cpp_ep_ptr->_parent._parent._listener->attachEvent(
//    *iox_subscriber,
//    iox::popo::SubscriberEvent::DATA_RECEIVED,
//    iox::popo::createNotificationCallback(on_incoming_data_callback, *cpp_ep_ptr))
//      .and_then([&]()
//        { returnval = DDS_RETCODE_OK; })
//      .or_else([&](auto)
//        { std::cerr << "failed to attach subscriber\n";});
//
//  return returnval;
//}
//
//
//// dds_loaned_sample_ops_t implementation
//
//static void iox_loaned_sample_free(dds_loaned_sample_t *loan)
//{
//  assert(loan);
//  delete reinterpret_cast<iox_loaned_sample*>(loan);
//}
//
//
//};  //namespace iox_psmx
//
//
//static char * get_config_option_value (const char *conf, const char *option_name)
//{
//  char *copy = dds_string_dup(conf), *cursor = copy, *tok;
//  while ((tok = ddsrt_strsep(&cursor, ",/|;")) != nullptr)
//  {
//    if (strlen(tok) == 0)
//      continue;
//    char *name = ddsrt_strsep(&tok, "=");
//    if (name == nullptr || tok == nullptr)
//    {
//      dds_free(copy);
//      return nullptr;
//    }
//    if (strcmp(name, option_name) == 0)
//    {
//      char *ret = dds_string_dup(tok);
//      dds_free(copy);
//      return ret;
//    }
//  }
//  dds_free(copy);
//  return nullptr;
//}
//
//static iox::log::LogLevel toLogLevel(const char *level_str) {
//  if (strcmp(level_str, "OFF") == 0) return iox::log::LogLevel::kOff;
//  if (strcmp(level_str, "FATAL") == 0) return iox::log::LogLevel::kFatal;
//  if (strcmp(level_str, "ERROR") == 0) return iox::log::LogLevel::kError;
//  if (strcmp(level_str, "WARN") == 0) return iox::log::LogLevel::kWarn;
//  if (strcmp(level_str, "INFO") == 0) return iox::log::LogLevel::kInfo;
//  if (strcmp(level_str, "DEBUG") == 0) return iox::log::LogLevel::kDebug;
//  if (strcmp(level_str, "VERBOSE") == 0) return iox::log::LogLevel::kVerbose;
//  return iox::log::LogLevel::kOff;
//}
//
//dds_return_t iox_create_psmx (struct dds_psmx **psmx, dds_loan_origin_type_t identifier, const char *config)
//{
//  assert(psmx);
//
//  char *service_name = get_config_option_value(config, "SERVICE_NAME");
//  char *log_level = get_config_option_value(config, "LOG_LEVEL");
//  if (log_level != nullptr) {
//    iox::log::LogManager::GetLogManager().SetDefaultLogLevel(toLogLevel(log_level), iox::log::LogLevelOutput::kHideLogLevel);
//  }
//
//  auto ptr = new iox_psmx::iox_psmx(identifier, service_name);
//
//  if (service_name)
//    dds_free(service_name);
//  if (log_level)
//    dds_free(log_level);
//
//  if (ptr == nullptr)
//    return DDS_RETCODE_ERROR;
//
//  *psmx = reinterpret_cast<struct dds_psmx*>(ptr);
//  return DDS_RETCODE_OK;
//}
