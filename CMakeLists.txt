cmake_minimum_required(VERSION 3.5...4.2)

project(qore-krb5-module VERSION 0.1.0)

include(CheckCXXCompilerFlag)

find_package(Qore 2.0 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(KRB5 REQUIRED krb5)
pkg_check_modules(GSSAPI REQUIRED krb5-gssapi)

include_directories(${KRB5_INCLUDE_DIRS})
include_directories(${GSSAPI_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_BINARY_DIR})

CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

check_cxx_compiler_flag(-fvisibility=hidden HAVE_GCC_VISIBILITY)

configure_file(${CMAKE_SOURCE_DIR}/cmake/config.h.cmake
               ${CMAKE_BINARY_DIR}/config.h)

set(QPP_SRC
    src/QC_Krb5Context.qpp
    src/QC_Krb5Credentials.qpp
    src/QC_Krb5CredentialCache.qpp
    src/QC_Krb5Keytab.qpp
    src/QC_Krb5Principal.qpp
    src/QC_GssCredential.qpp
    src/QC_GssClientContext.qpp
)

set(CPP_SRC
    src/krb5-module.cpp
)

set(MODULE_DOX_INPUT
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/doxygen
)

qore_wrap_qpp_value(QPP_SOURCES DOXLIST _dox_src METALIST QPP_META_SRC ${QPP_SRC})

set(module_name "krb5")

set(QORE_DOX_TMPL_SRC
    docs/mainpage.doxygen.tmpl
    docs/security.doxygen.tmpl
    docs/examples.doxygen.tmpl
)

if (DEFINED ENV{DOXYGEN_EXECUTABLE})
    set(DOXYGEN_EXECUTABLE $ENV{DOXYGEN_EXECUTABLE})
endif()

add_library(${module_name} MODULE ${CPP_SRC} ${QPP_SOURCES})
target_include_directories(${module_name} PUBLIC ${KRB5_INCLUDE_DIRS} ${GSSAPI_INCLUDE_DIRS})

set(KRB5_LINK_FLAGS ${KRB5_LDFLAGS} ${GSSAPI_LDFLAGS})
qore_external_binary_module(${module_name} ${PROJECT_VERSION} ${KRB5_LINK_FLAGS})

qore_external_user_module("qlib/Krb5" "")

install(PROGRAMS
    bin/qklist
    DESTINATION bin
)

qore_dist(${PROJECT_VERSION})

if (COMMAND qore_install_qpp_metadata)
    qore_install_qpp_metadata(${module_name} ${QPP_META_SRC})
else()
    install(FILES ${QPP_META_SRC}
            DESTINATION ${CMAKE_INSTALL_DATADIR}/qore/metadata)
endif()

qore_config_info()

if (DOXYGEN_FOUND)
    qore_wrap_dox(QORE_DOX_SRC ${QORE_DOX_TMPL_SRC})
    add_custom_target(QORE_MOD_DOX_FILES DEPENDS ${QORE_DOX_SRC})
    add_dependencies(docs-module QORE_MOD_DOX_FILES)
endif()
