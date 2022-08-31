#
# Copyright(c) 2006 to 2022 ZettaScale Technology and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
include(CUnit)

idlc_generate(TARGET RoundTrip FILES RoundTrip.idl)
idlc_generate(TARGET Space FILES Space.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET TypesArrayKey FILES TypesArrayKey.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET WriteTypes FILES WriteTypes.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET InstanceHandleTypes FILES InstanceHandleTypes.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET RWData FILES RWData.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET CreateWriter FILES CreateWriter.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET DataRepresentationTypes FILES DataRepresentationTypes.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET MinXcdrVersion FILES MinXcdrVersion.idl)
idlc_generate(TARGET CdrStreamOptimize FILES CdrStreamOptimize.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET CdrStreamSkipDefault FILES CdrStreamSkipDefault.idl)
idlc_generate(TARGET VIDataModels FILES VIDataModels.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET CdrStreamDataTypeInfo FILES CdrStreamDataTypeInfo.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET Array100 FILES Array100.idl WARNINGS no-implicit-extensibility)
idlc_generate(TARGET DynamicData FILES DynamicData.idl WARNINGS no-implicit-extensibility)
if(ENABLE_TYPE_DISCOVERY)
  idlc_generate(TARGET XSpace FILES XSpace.idl XSpaceEnum.idl XSpaceMustUnderstand.idl XSpaceTypeConsistencyEnforcement.idl WARNINGS no-implicit-extensibility no-inherit-appendable)
  idlc_generate(TARGET XSpaceNoTypeInfo FILES XSpaceNoTypeInfo.idl NO_TYPE_INFO WARNINGS no-implicit-extensibility)
  idlc_generate(TARGET TypeBuilderTypes FILES TypeBuilderTypes.idl WARNINGS no-implicit-extensibility)
endif()

set(ddsc_test_sources
    "asymdisconnect.c"
    "basic.c"
    "builtin_topics.c"
    "cdr.c"
    "config.c"
    "data_avail_stress.c"
    "destorder.c"
    "discstress.c"
    "dispose.c"
    "domain.c"
    "domain_torture.c"
    "entity_api.c"
    "entity_hierarchy.c"
    "entity_status.c"
    "err.c"
    "filter.c"
    "instance_get_key.c"
    "instance_handle.c"
    "listener.c"
    "liveliness.c"
    "loan.c"
    "multi_sertype.c"
    "nwpart.c"
    "participant.c"
    "pp_lease_dur.c"
    "publisher.c"
    "qos.c"
    "qosmatch.c"
    "querycondition.c"
    "guardcondition.c"
    "readcondition.c"
    "reader.c"
    "reader_iterator.c"
    "read_instance.c"
    "register.c"
    "subscriber.c"
    "take_instance.c"
    "time.c"
    "time_based_filter.c"
    "topic.c"
    "topic_find_local.c"
    "transientlocal.c"
    "types.c"
    "uninitialized.c"
    "unregister.c"
    "unsupported.c"
    "userdata.c"
    "waitset.c"
    "waitset_torture.c"
    "whc.c"
    "write.c"
    "write_various_types.c"
    "writer.c"
    "test_util.c"
    "test_util.h"
    "test_common.h"
    "test_common.c"
    "test_oneliner.c"
    "test_oneliner.h"
    "cdrstream.c"
    "psmx.c"
  )

if(ENABLE_LIFESPAN)
  list(APPEND ddsc_test_sources "lifespan.c")
endif()

if(ENABLE_DEADLINE_MISSED)
  list(APPEND ddsc_test_sources "deadline.c")
endif()

if(ENABLE_TYPE_DISCOVERY)
  list(APPEND ddsc_test_sources
    "xtypes.c"
    "data_representation.c"
    "typebuilder.c"
    "dynamic_type.c"
  )
endif()

if(ENABLE_TOPIC_DISCOVERY)
  list(APPEND ddsc_test_sources
    "typelookup.c"
    "topic_discovery.c"
    "topic_find_global.c")
endif()

add_cunit_executable(cunit_ddsc ${ddsc_test_sources})
target_include_directories(
  cunit_ddsc PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/src/include/>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsc/src>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsi/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsi/src>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../cdr/include>")

target_link_libraries(cunit_ddsc PRIVATE
  RoundTrip Space TypesArrayKey WriteTypes InstanceHandleTypes RWData CreateWriter DataRepresentationTypes MinXcdrVersion CdrStreamOptimize CdrStreamSkipDefault CdrStreamDataTypeInfo VIDataModels DynamicData Array100 ddsc)

if(ENABLE_TYPE_DISCOVERY)
  target_link_libraries(cunit_ddsc PRIVATE
  XSpace XSpaceNoTypeInfo TypeBuilderTypes)
endif()

# Setup environment for config-tests
get_test_property(CUnit_ddsc_config_simple_udp ENVIRONMENT CUnit_ddsc_config_simple_udp_env)
set(CUnit_ddsc_config_simple_udp_file "${CMAKE_CURRENT_LIST_DIR}/config_simple_udp.xml")
set(CUnit_ddsc_config_simple_udp_uri "file://${CUnit_ddsc_config_simple_udp_file}")
set(CUnit_ddsc_config_simple_udp_max_participants "0")
set(CUnit_ddsc_config_simple_udp_env "CYCLONEDDS_URI=${CUnit_ddsc_config_simple_udp_uri};MAX_PARTICIPANTS=${CUnit_ddsc_config_simple_udp_max_participants};${CUnit_ddsc_config_simple_udp_env}")
set_tests_properties(
	CUnit_ddsc_config_simple_udp
	PROPERTIES
		REQUIRED_FILES ${CUnit_ddsc_config_simple_udp_file}
		ENVIRONMENT "${CUnit_ddsc_config_simple_udp_env}")

configure_file("deadline_update.h.in" "deadline_update.h")

if(ENABLE_DEADLINE_MISSED)
  foreach(t
      basic
      instances
      update
      writer_types)
    set_tests_properties(CUnit_ddsc_deadline_${t} PROPERTIES RUN_SERIAL TRUE)
  endforeach()
endif()

# PSMX implementation with Cyclone as transport, for testing
idlc_generate(TARGET psmx_cdds_data FILES psmx_cdds_data.idl)
set(psmx_cdds_sources
  "psmx_cdds_impl.c"
  "psmx_cdds_impl.h")
add_library(psmx_cdds SHARED ${psmx_cdds_sources})
target_include_directories(
  psmx_cdds PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsi/include>")
target_link_libraries(psmx_cdds PRIVATE ddsc psmx_cdds_data)

get_test_property(CUnit_ddsc_psmx_basic ENVIRONMENT CUnit_ddsc_psmx_basic_env)
set(CUnit_ddsc_psmx_basic_file "${CMAKE_CURRENT_LIST_DIR}/config_psmx.xml")
set(CUnit_ddsc_psmx_basic_uri "file://${CUnit_ddsc_psmx_basic_file}")
set(CUnit_ddsc_psmx_basic_env "CDDS_PSMX_LIB=$<TARGET_FILE:psmx_cdds>;CYCLONEDDS_URI=${CUnit_ddsc_psmx_basic_uri}")
set_tests_properties(
	CUnit_ddsc_psmx_basic
	PROPERTIES
		REQUIRED_FILES ${CUnit_ddsc_psmx_basic_file}
		ENVIRONMENT "${CUnit_ddsc_psmx_basic_env}")

configure_file("config_env.h.in" "config_env.h" @ONLY)

add_executable(oneliner
  "oneliner.c"
  "test_oneliner.c"
  "test_oneliner.h"
  "test_util.c"
  "test_util.h")
target_include_directories(
  oneliner PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/src/include/>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsc/src>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsi/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../ddsi/src>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../cdr/include>")

target_link_libraries(oneliner PRIVATE RoundTrip Space ddsc)
