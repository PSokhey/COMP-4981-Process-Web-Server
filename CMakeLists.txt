cmake_minimum_required(VERSION 3.0.0)

project(process-server
        VERSION 0.0.1
        DESCRIPTION ""
        LANGUAGES C)

set(CMAKE_C_STANDARD 17)

option(DC_BUILD_SANITIZE "Build with sanitize" OFF)
if(NOT DC_BUILD_SANITIZE)
    set(SANITIZE TRUE)
endif()

set(SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(TESTS_DIR ${PROJECT_SOURCE_DIR}/tests)

set(PROCESS_SERVER_SOURCE_LIST
        )
set(PROCESS_SERVER_SOURCE_MAIN
        ${SOURCE_DIR}/main-process-server.c
        )
set(PROCESS_SERVER_HEADER_LIST
        ${INCLUDE_DIR}/processor.h
        )
set(PROCESS_SERVER_REQUIRED_LIBRARIES_LIST
        dc_error
        dc_env
        dc_c
        dc_posix
        dc_posix_xsi
        dc_unix
        dc_util
        )
set(CLIENT_SOURCE_LIST
        )
set(CLIENT_SOURCE_MAIN
        ${SOURCE_DIR}/main-client.c
        )
set(CLIENT_HEADER_LIST
        )
set(CLIENT_REQUIRED_LIBRARIES_LIST
        )
set(ECHO_SOURCE_LIST
        ${SOURCE_DIR}/echo.c
        ${SOURCE_DIR}/database.c
        ${SOURCE_DIR}/error.c
        )
set(ECHO_HEADER_LIST
        ${INCLUDE_DIR}/processor.h
        ${INCLUDE_DIR}/database.h
        ${INCLUDE_DIR}/error.h
        )
set(ECHO_REQUIRED_LIBRARIES_LIST
        dc_error
        dc_env
        dc_c
        dc_posix
        dc_util
        )
set(TEST_HEADER_LIST
        )
set(TEST_SOURCE_LIST
        )
set(TEST_REQUIRED_LIBRARIES_LIST
        )

list(APPEND TEST_REQUIRED_LIBRARIES_LIST
        ${BINARY_REQUIRED_LIBRARIES_LIST}
        )

function(add_compile_definitions_platform)
    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        add_compile_definitions(_DARWIN_C_SOURCE)
    endif ()

    if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        add_compile_definitions(__BSD_VISIBLE)
    endif ()
endfunction()

function(add_compile_options_list)
    include(CheckCCompilerFlag)
    foreach (FLAG IN LISTS ARGN)
        string(REPLACE "-" "" FLAG_NO_HYPHEN ${FLAG})
        check_c_compiler_flag(${FLAG} COMPILER_SUPPORTS_${FLAG_NO_HYPHEN})
        if (COMPILER_SUPPORTS_${FLAG_NO_HYPHEN})
            add_compile_options(${FLAG})
        endif ()
    endforeach ()
endfunction()

function(set_compiler_flags)
    list(APPEND COMPILER_FLAGS
            "-Wall"
            "-Wextra"
            "-Wpedantic"
            "-Wshadow"
            "-Wstrict-overflow=4"
            "-Wswitch-default"
            "-Wswitch-enum"
            "-Wunused"
            "-Wunused-macros"
            "-Wdate-time"
            "-Winvalid-pch"
            "-Wmissing-declarations"
            "-Wmissing-include-dirs"
            "-Wmissing-prototypes"
            "-Wstrict-prototypes"
            "-Wundef"
            "-Wnull-dereference"
            "-Wstack-protector"
            "-Wdouble-promotion"
            "-Wvla"
            "-Walloca"
            "-Woverlength-strings"
            "-Wdisabled-optimization"
            "-Winline"
            "-Wcast-qual"
            "-Wfloat-equal"
            "-Wformat=2"
            "-Wfree-nonheap-object"
            "-Wshift-overflow"
            "-Wwrite-strings"
            "-Wunsuffixed-float-constants"
            "-Warith-conversion"
            "-Wunsafe-loop-optimizations"
            "-Wvector-operation-performance"
            "-Walloc-zero"
            "-Wtrampolines"
            "-Wtsan"
            "-Wformat-overflow=2"
            "-Wformat-signedness"
            "-Wjump-misses-init"
            "-Wformat-truncation=2"
            )

    if (${SANITIZE})
        list(APPEND COMPILER_FLAGS
                "-fsanitize=pointer-compare"
                "-fsanitize=pointer-subtract"
                "-fsanitize=undefined"
                "-fcf-protection=full"
                "-fharden-control-flow-redundancy"
                "-fstack-protector=all"
                "-finstrument-functions"
                "-fsanitize=leak"
                "-fno-delete-null-pointer-checks"
                "-fsanitize=shift"
                "-fsanitize=signed-integer-overflow"
                "-fsanitize=integer-divide-by-zero"
                "-fsanitize=unreachable"
                "-fsanitize=vla-bound"
                "-fsanitize=null"
                "-fsanitize=return"
                "-fsanitize=bool"
                "-fsanitize=enum"
                "-fsanitize=bounds"
                "-fsanitize=float-divide-by-zero"
                "-fsanitize=float-cast-overflow"
                "-fsanitize=nonnull-attribute"
                "-fsanitize=returns-nonnull-attribute"
                "-fsanitize=alignment"
                "-fsanitize=vptr"
                "-fsanitize=builtin"
                #                "-fsanitize=bounds-strict"
                "-fsanitize=pointer-overflow"
                "-fsanitize=cfi"
                "-fsanitize=cfi-icall"
                "-fsanitize=cfi-vcall"
                "-fsanitize=cfi-nvcall"
                "-fsanitize=cfi-derived-cast"
                "-fsanitize=cfi-unrelated-cast"
                "-fsanitize=cfi-unrelated-access"
                "-fsanitize=cfi-icall-general"
                "-fsanitize=cfi-vcall-general"
                "-fsanitize=cfi-nvcall-general"
                "-fsanitize=cfi-derived-cast-general"
                "-fsanitize=cfi-unrelated-cast-general"
                "-fsanitize=cfi-unrelated-access-general"
                "-fsanitize=cfi-icall-lto"
                "-fsanitize=cfi-vcall-lto"
                "-fsanitize=cfi-nvcall-lto"
                "-fsanitize=cfi-derived-cast-lto"
                "-fsanitize=cfi-unrelated-cast-lto"
                "-fsanitize=cfi-unrelated-access-lto"
                )

        if ("NOT ${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            list(APPEND COMPILER_FLAGS
                    "-fsanitize=object-size"
                    )
        endif ()
    endif ()

    add_compile_options_list(${COMPILER_FLAGS})

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
endfunction()

function(doxygen)
    find_package(Doxygen
            REQUIRED
            REQUIRED dot
            OPTIONAL_COMPONENTS mscgen dia)

    set(DOXYGEN_ALWAYS_DETAILED_SEC YES)
    set(DOXYGEN_REPEAT_BRIEF YES)
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_JAVADOC_AUTOBRIEF YES)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_WARNINGS YES)
    set(DOXYGEN_QUIET YES)

    doxygen_add_docs(doxygen
            ${HEADER_LIST}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            COMMENT "Generating Doxygen documentation for shared_libraries")

endfunction()

function(clangtidy target source_files main_source_files)
    set(CLANG_TIDY_CHECKS "*")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-altera-id-dependent-backward-branch")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-altera-struct-pack-align")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-altera-unroll-loops")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-android-cloexec-accept")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-android-cloexec-creat")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-android-cloexec-dup")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-android-cloexec-open")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-android-cloexec-pipe")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-android-cloexec-socket")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-bugprone-easily-swappable-parameters")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-cert-dcl03-c")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-analyzer-deadcode.DeadStores")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-analyzer-security.insecureAPI.strcpy")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-cast-align")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-format-nonliteral")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-incompatible-pointer-types-discards-qualifiers")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-unknown-warning-option")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-unused-but-set-variable")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-unused-function")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-unused-parameter")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-unused-variable")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-clang-diagnostic-vla")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-cppcoreguidelines-init-variables")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-google-readability-todo")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-hicpp-static-assert")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-llvmlibc-restrict-system-libc-headers")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-misc-static-assert")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-misc-unused-parameters")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-modernize-macro-to-enum")
    set(CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS},-readability-identifier-length")

    find_program(CLANG_TIDY_EXE NAMES "clang-tidy")

    if (CLANG_TIDY_EXE)
        set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_EXE}")

        if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
            file(GLOB CLANG_DIRS "/Library/Developer/CommandLineTools/usr/lib/clang/*")
            list(SORT CLANG_DIRS)
            list(REVERSE CLANG_DIRS)

            foreach (dir ${CLANG_DIRS})
                if (EXISTS ${dir}/include/stdbool.h)
                    set(STDBOOL_INCLUDE_DIR ${dir}/include)
                    break()
                endif ()
            endforeach ()

            if (NOT STDBOOL_INCLUDE_DIR)
                message(FATAL_ERROR "Cannot find the stdbool.h file in any of the directories in /Library/Developer/CommandLineTools/usr/lib/clang/")
            endif ()

            set(EXTRA_ARGS "--extra-arg=-I${STDBOOL_INCLUDE_DIR}")
        else ()
            set(EXTRA_ARGS "")
        endif ()

        set(CLANG_TIDY_TARGET_NAME "clang-tidy-${target}")
        add_custom_target(${CLANG_TIDY_TARGET_NAME} ALL
                COMMAND ${CLANG_TIDY_EXE} -p ${CMAKE_BINARY_DIR} ${EXTRA_ARGS} -checks=${CLANG_TIDY_CHECKS};--quiet ${${source_files}} ${${main_source_files}}
                COMMENT "Running clang-tidy"
                VERBATIM)
    endif ()
endfunction()

function(link_libraries target_name libraries_list)
    foreach (LIBRARY ${${libraries_list}})
        find_library(LIB ${LIBRARY} REQUIRED)
        get_filename_component(LIB_DIR ${LIB} DIRECTORY)
        link_directories(${LIB_DIR})
        target_link_libraries(${target_name} PRIVATE ${LIB})
        unset(LIB CACHE)
        unset(LIB_DIR CACHE)
    endforeach ()
    target_link_libraries(${target_name} PRIVATE -lgdbm)
    target_link_libraries(${target_name} PRIVATE -lgdbm_compat)
endfunction()

function(link_ncurses_libraries target_name)
    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        find_library(LIBMENU menu REQUIRED NO_DEFAULT_PATH PATHS /usr/local/opt/ncurses/lib)
        find_library(LIBNCURSES ncurses REQUIRED NO_DEFAULT_PATH PATHS /usr/local/opt/ncurses/lib)
        target_link_libraries(${target_name} PUBLIC /usr/local/opt/ncurses/lib/libmenu.dylib)
        target_link_libraries(${target_name} PUBLIC /usr/local/opt/ncurses/lib/libncurses.dylib)
    else ()
        find_library(LIBMENU menu REQUIRED)
        find_library(LIBNCURSES ncurses REQUIRED)
        target_link_libraries(${target_name} PUBLIC ${LIBMENU})
        target_link_libraries(${target_name} PUBLIC ${LIBNCURSES})
    endif ()
endfunction()

function(link_gtk_libraries target_name)
endfunction()

function(add_executable_target target_name source_files main_source_files header_files libraries_files link_libraries_fn install_name)
    add_executable(${target_name} ${${source_files}} ${${main_source_files}} ${${header_files}})

    list(LENGTH ${libraries_files} list_length)
    if (list_length)
        link_libraries(${target_name} ${libraries_files})
    endif ()

    target_link_libraries(${target_name} PRIVATE -fsanitize=undefined)

    if (link_libraries_fn STREQUAL "link_ncurses_libraries")
        link_ncurses_libraries(${target_name})
    elseif (link_libraries_fn STREQUAL "link_gtk_libraries")
        link_gtk_libraries(${target_name})
    endif ()

    add_dependencies(${target_name} doxygen)
    add_dependencies(${target_name} clang-tidy-${target_name})
    clangtidy(${target_name} ${source_files} ${main_source_files})

    if (NOT "${install_name}" STREQUAL "")
        set_target_properties(${target_name} PROPERTIES OUTPUT_NAME ${install_name})
        install(TARGETS ${target_name} DESTINATION bin)
    endif ()
endfunction()

function(add_library_target target_name library_type source_files header_files libraries_files link_libraries_fn install_name)
    add_library(${target_name} ${library_type} ${${source_files}} ${${main_source_files}} ${${header_files}})

    list(LENGTH ${libraries_files} list_length)
    if(list_length)
        link_libraries(${target_name} ${libraries_files})
    endif()

    target_link_libraries(${target_name} PRIVATE -fsanitize=undefined)

    if(link_libraries_fn STREQUAL "link_ncurses_libraries")
        link_ncurses_libraries(${target_name})
    elseif(link_libraries_fn STREQUAL "link_gtk_libraries")
        link_gtk_libraries(${target_name})
    endif()

    add_dependencies(${target_name} doxygen)
    add_dependencies(${target_name} clang-tidy-${target_name})
    clangtidy(${target_name} ${source_files} "")

    if(NOT "${install_name}" STREQUAL "")
        set_target_properties(${target_name} PROPERTIES OUTPUT_NAME ${install_name})
        install(TARGETS ${target_name} DESTINATION bin)
    endif ()
endfunction()

function(add_test_target target_name source_files header_files test_source_files test_header_files libraries_files link_libraries_fn)
    add_executable(${target_name} ${${source_files}} ${${HEADER_LIST}} ${${test_source_files}} ${${test_header_files}})
    find_library(CGREEN_LIBRARY NAMES cgreen)
    find_path(CGREEN_INCLUDE_DIR cgreen/cgreen.h)
    include_directories(${CGREEN_INCLUDE_DIR})
    target_link_libraries(${target_name} PRIVATE ${CGREEN_LIBRARY})
    target_compile_definitions(${target_name} PRIVATE ${DEFINITIONS_LIST})

    list(LENGTH ${libraries_files} list_length)
    if (list_length)
        link_libraries(${target_name} ${libraries_files})
    endif ()

    target_link_libraries(${target_name} PRIVATE -fsanitize=undefined)

    if (link_libraries_fn STREQUAL "link_ncurses_libraries")
        link_ncurses_libraries(${target_name})
    elseif (link_libraries_fn STREQUAL "link_gtk_libraries")
        link_gtk_libraries(${target_name})
    endif ()

    add_test(NAME tests COMMAND tests)

endfunction()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib;${CMAKE_INSTALL_PREFIX}/lib64")
    set(CMAKE_BUILD_RPATH "${CMAKE_INSTALL_PREFIX}/lib;${CMAKE_INSTALL_PREFIX}/lib64")
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include_directories(${INCLUDE_DIR})
add_compile_definitions(_POSIX_C_SOURCE=200809L)
add_compile_definitions(_XOPEN_SOURCE=700)
add_compile_definitions(_GNU_SOURCE)
add_compile_definitions_platform()
set_compiler_flags()
doxygen()

find_path(ENV_INCLUDE_DIR dc_env/env.h)
include_directories(${ENV_INCLUDE_DIR})
find_path(ENV_INCLUDE_DIR dc_env/env.h)
include_directories(${ENV_INCLUDE_DIR})

add_executable_target(client CLIENT_SOURCE_LIST CLIENT_SOURCE_MAIN CLIENT_HEADER_LIST CLIENT_REQUIRED_LIBRARIES_LIST "" "")
add_executable_target(process-server PROCESS_SERVER_SOURCE_LIST PROCESS_SERVER_SOURCE_MAIN PROCESS_SERVER_HEADER_LIST PROCESS_SERVER_REQUIRED_LIBRARIES_LIST "" "")
add_library_target(echo SHARED ECHO_SOURCE_LIST ECHO_HEADER_LIST ECHO_REQUIRED_LIBRARIES_LIST "" "")