cmake_minimum_required(VERSION 3.16)

project(UniqueCodePerDevice VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_GUI "Build the Qt GUI tools" ON)
option(BUILD_SHARED_LICENSE "Build the license shared library" ON)
option(BUILD_TESTS "Build the core round-trip test" OFF)
option(ENABLE_WINDOWS_SELF_HASH "Enable PE .text self-hash protection on Windows" ON)

if(MSVC)
    add_compile_options(/utf-8)
endif()

if(NOT WIN32)
    add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
endif()

set(GEN_DIR "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GEN_DIR}")

if(WIN32)
    enable_language(RC)
    set(APP_ICON_RC "${GEN_DIR}/app_icon.rc")
    file(WRITE "${APP_ICON_RC}" "IDI_ICON1 ICON \"${CMAKE_SOURCE_DIR}/logo.ico\"\n")
endif()

if(NOT EXISTS "${CMAKE_SOURCE_DIR}/key/sky_share.bin" OR
   NOT EXISTS "${CMAKE_SOURCE_DIR}/key/sky.bin")
    message(FATAL_ERROR "key/sky_share.bin and key/sky.bin are required. Run the key generator first.")
endif()

add_executable(embed_key src/embed_key.c)
target_include_directories(embed_key PRIVATE include)

set(EMBEDDED_PUBKEY "${GEN_DIR}/embedded_pubkey.h")
add_custom_command(
    OUTPUT "${EMBEDDED_PUBKEY}"
    COMMAND embed_key "${CMAKE_SOURCE_DIR}/key/sky_share.bin" "${EMBEDDED_PUBKEY}"
            EMBEDDED_PUBLIC_KEY EMBEDDED_PUBKEY_H
    DEPENDS embed_key "${CMAKE_SOURCE_DIR}/key/sky_share.bin"
    COMMENT "Embedding ECDSA public key")

set(EMBEDDED_PRIVKEY "${GEN_DIR}/embedded_privkey.h")
add_custom_command(
    OUTPUT "${EMBEDDED_PRIVKEY}"
    COMMAND embed_key "${CMAKE_SOURCE_DIR}/key/sky.bin" "${EMBEDDED_PRIVKEY}"
            EMBEDDED_PRIVATE_KEY EMBEDDED_PRIVKEY_H
    DEPENDS embed_key "${CMAKE_SOURCE_DIR}/key/sky.bin"
    COMMENT "Embedding ECDSA private key")

set(CORE_SOURCES
    src/license.c
    src/license_dll.c
    src/key.c
    src/sha256.c
)

if(WIN32)
    list(APPEND CORE_SOURCES
        src/platform_win32.c
        src/hardware.c
        src/ntp_client.c
        src/time_anchor.c
        src/anti_debug.c
        src/ecdsa.c
        src/license_backup_win32.c
    )
else()
    list(APPEND CORE_SOURCES
        src/platform_posix.c
        src/hardware_posix.c
        src/ntp_posix.c
        src/time_anchor_posix.c
        src/anti_debug_posix.c
        src/ecdsa_openssl.c
        src/license_backup_posix.c
    )
endif()

set(CORE_LIBS "")
if(WIN32)
    list(APPEND CORE_LIBS user32 gdi32 advapi32 iphlpapi ws2_32 psapi bcrypt shell32)
else()
    find_package(OpenSSL REQUIRED)
    list(APPEND CORE_LIBS OpenSSL::Crypto)
endif()

function(configure_core_target target)
    target_include_directories(${target} PUBLIC include)
    if(WIN32)
        target_link_libraries(${target} PUBLIC ${CORE_LIBS})
    else()
        target_link_libraries(${target} PUBLIC ${CORE_LIBS})
        set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    endif()
endfunction()

add_library(license_core STATIC ${CORE_SOURCES} "${EMBEDDED_PUBKEY}")
configure_core_target(license_core)
target_include_directories(license_core PUBLIC "${GEN_DIR}")
target_compile_definitions(license_core PUBLIC LICENSE_STATIC)

add_library(license_core_signer STATIC ${CORE_SOURCES} "${EMBEDDED_PUBKEY}" "${EMBEDDED_PRIVKEY}")
configure_core_target(license_core_signer)
target_include_directories(license_core_signer PUBLIC "${GEN_DIR}")
target_compile_definitions(license_core_signer PUBLIC ECDSA_SIGN_ENABLED LICENSE_STATIC)
if(WIN32)
    target_sources(license_core_signer PRIVATE src/ecdsa_sign.c)
endif()

if(BUILD_TESTS)
    add_executable(core_roundtrip tests/core_roundtrip.c)
    target_link_libraries(core_roundtrip PRIVATE license_core_signer)
endif()

if(WIN32)
    set(KEYGEN_CORE_SOURCES
        src/ecdsa.c
        src/platform_win32.c
        src/sha256.c
        src/key.c
        "${EMBEDDED_PUBKEY}")
    set(KEYGEN_CORE_LIBS bcrypt user32)
else()
    set(KEYGEN_CORE_SOURCES
        src/ecdsa_openssl.c
        src/platform_posix.c
        src/sha256.c
        src/key.c
        "${EMBEDDED_PUBKEY}")
    set(KEYGEN_CORE_LIBS OpenSSL::Crypto)
endif()

add_library(license_keygen_core STATIC ${KEYGEN_CORE_SOURCES})
target_include_directories(license_keygen_core PUBLIC include "${GEN_DIR}")
target_compile_definitions(license_keygen_core PUBLIC LICENSE_STATIC)
target_link_libraries(license_keygen_core PUBLIC ${KEYGEN_CORE_LIBS})

if(BUILD_SHARED_LICENSE)
    if(WIN32 AND ENABLE_WINDOWS_SELF_HASH)
        set(STAGE1_DIR "${CMAKE_BINARY_DIR}/stage1")
        file(MAKE_DIRECTORY "${STAGE1_DIR}")
        file(WRITE "${STAGE1_DIR}/dll_hash.h"
            "#ifndef LICENSE_DLL_CODE_SHA256_H\n"
            "#define LICENSE_DLL_CODE_SHA256_H\n"
            "#define LICENSE_DLL_CODE_SHA256 \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
            "#define LICENSE_DLL_FILE_SHA256 \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
            "#endif\n")

        add_executable(hashgen
            src/hashgen.c
            src/pe_digest.c
            src/sha256.c
            src/platform_win32.c)
        target_include_directories(hashgen PRIVATE include)
        target_link_libraries(hashgen PRIVATE bcrypt)

        add_library(license_stage1 SHARED ${CORE_SOURCES} "${EMBEDDED_PUBKEY}")
        target_include_directories(license_stage1 BEFORE PRIVATE "${STAGE1_DIR}")
        target_include_directories(license_stage1 PUBLIC include "${GEN_DIR}")
        target_compile_definitions(license_stage1 PRIVATE LICENSE_SELF_HASH LICENSE_DLL_EXPORTS)
        target_link_libraries(license_stage1 PRIVATE ${CORE_LIBS})
        set_target_properties(license_stage1 PROPERTIES OUTPUT_NAME "license_stage1")

        set(GENERATED_DLL_HASH "${GEN_DIR}/dll_hash.h")
        add_custom_command(
            OUTPUT "${GENERATED_DLL_HASH}"
            COMMAND hashgen "$<TARGET_FILE:license_stage1>" "${GENERATED_DLL_HASH}"
            DEPENDS license_stage1 hashgen
            COMMENT "Computing license DLL .text section hash")
        add_custom_target(license_hash_gen DEPENDS "${GENERATED_DLL_HASH}")

        add_library(license SHARED ${CORE_SOURCES} "${EMBEDDED_PUBKEY}" "${GENERATED_DLL_HASH}")
        target_include_directories(license BEFORE PRIVATE "${GEN_DIR}")
        target_include_directories(license PUBLIC include)
        target_compile_definitions(license PRIVATE LICENSE_SELF_HASH LICENSE_DLL_EXPORTS)
        target_link_libraries(license PRIVATE ${CORE_LIBS})
        add_dependencies(license license_hash_gen)
        set_target_properties(license PROPERTIES OUTPUT_NAME "license")
    else()
        add_library(license SHARED ${CORE_SOURCES} "${EMBEDDED_PUBKEY}")
        target_include_directories(license PUBLIC include "${GEN_DIR}")
        target_compile_definitions(license PRIVATE LICENSE_DLL_EXPORTS)
        target_link_libraries(license PRIVATE ${CORE_LIBS})
        set_target_properties(license PROPERTIES OUTPUT_NAME "license")
    endif()
endif()

if(BUILD_GUI)
    find_package(Qt6 COMPONENTS Widgets QUIET)
    if(NOT Qt6_FOUND)
        message(WARNING "Qt6 not found. GUI tools will not be built. "
                        "Install Qt 6 and pass -DCMAKE_PREFIX_PATH=<Qt6>/lib/cmake.")
    else()
        add_library(license_qt_common STATIC src/qt/common/licensecore.cpp)
        target_link_libraries(license_qt_common PUBLIC Qt6::Widgets)
        target_compile_definitions(license_qt_common PUBLIC LICENSE_STATIC)
        target_include_directories(license_qt_common PUBLIC
            include "${GEN_DIR}" src/qt/common)

        foreach(app_name license_system generator dat_viewer)
            set(app_sources src/qt/${app_name}/main.cpp)
            if(WIN32)
                list(APPEND app_sources "${APP_ICON_RC}")
            endif()
            qt_add_executable(${app_name} ${app_sources})
            target_link_libraries(${app_name} PRIVATE license_qt_common)
            if(WIN32)
                set_target_properties(${app_name} PROPERTIES WIN32_EXECUTABLE TRUE)
            endif()
            if(APPLE)
                set_target_properties(${app_name} PROPERTIES MACOSX_BUNDLE TRUE)
            endif()
        endforeach()

        set(keygen_sources src/qt/keygen/main.cpp)
        if(WIN32)
            list(APPEND keygen_sources "${APP_ICON_RC}")
        endif()
        qt_add_executable(keygen ${keygen_sources})
        target_link_libraries(keygen PRIVATE Qt6::Widgets license_keygen_core)
        target_include_directories(keygen PRIVATE src/qt/common)
        if(WIN32)
            set_target_properties(keygen PROPERTIES WIN32_EXECUTABLE TRUE)
        endif()
        if(APPLE)
            set_target_properties(keygen PROPERTIES MACOSX_BUNDLE TRUE)
        endif()

        target_link_libraries(license_system PRIVATE license_core)
        target_link_libraries(dat_viewer PRIVATE license_core)
        target_link_libraries(generator PRIVATE license_core_signer)
    endif()
endif()
