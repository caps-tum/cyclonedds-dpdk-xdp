#
# Copyright(c) 2023 ZettaScale Technology and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
cmake_minimum_required(VERSION 3.10)
project(CycloneDDS-PSMX-DPDK VERSION 0.11.0 LANGUAGES C CXX)

find_package(PkgConfig REQUIRED)

pkg_check_modules(libdpdk REQUIRED IMPORTED_TARGET libdpdk)

add_library(psmx_dpdk SHARED "src/psmx_dpdk_impl.cpp")

set_target_properties(psmx_dpdk PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(psmx_dpdk PRIVATE "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_link_libraries(psmx_dpdk PRIVATE ddsc libdpdk)

install(TARGETS psmx_dpdk
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

