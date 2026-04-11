cmake_minimum_required(VERSION 3.5...4.2)

project(qore-krb5-module VERSION 1.0.0)

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
    docs/usecases.doxygen.tmpl
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

qore_external_user_module("qlib/Krb5Util" "")

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

    # Two-phase doc build so the binary module's mainpage can @ref into Krb5Util.
    # Prefer the qore_binary_module_two_phase_docs() helper from recent Qore
    # releases; fall back to an inline implementation on older Qore versions
    # that predate the macro. Both use the correct ../../Krb5Util/html relative
    # path (two levels of ".." to escape the binary module's own html/ and
    # docs/${module_name}/ directories back to the shared docs/ root).
    if (COMMAND qore_binary_module_two_phase_docs)
        qore_binary_module_two_phase_docs(${module_name} "Krb5Util")
    else()
        file(APPEND ${CMAKE_BINARY_DIR}/Doxyfile
            "\n# Suppress warnings for initial pass (no user module TAGFILES available)\nWARN_IF_DOC_ERROR = NO\n")
        file(COPY_FILE ${CMAKE_BINARY_DIR}/Doxyfile ${CMAKE_BINARY_DIR}/Doxyfile.final)
        file(APPEND ${CMAKE_BINARY_DIR}/Doxyfile.final
            "\n# Final pass: enable user module cross-references and re-enable doc error warnings\nTAGFILES = ${CMAKE_BINARY_DIR}/Krb5Util.tag=../../Krb5Util/html\nWARN_IF_DOC_ERROR = YES\n")
        add_custom_target(docs-module-final
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile.final
            COMMAND ${QORE_DOCS_ENV} ${QORE_QDX_COMMAND} --post ${CMAKE_BINARY_DIR}/docs/${module_name}/html ${CMAKE_BINARY_DIR}/docs/${module_name}/html/search
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen (final pass with Krb5Util cross-references)"
            VERBATIM
        )
        add_dependencies(docs-module-final docs-Krb5Util)
        add_dependencies(docs docs-module-final)
    endif()
endif()
