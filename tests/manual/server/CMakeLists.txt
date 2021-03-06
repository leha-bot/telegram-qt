cmake_minimum_required(VERSION 3.1)

project(TelegramTestServer
    LANGUAGES CXX
)

set(OVERRIDE_CXX_STANDARD 11 CACHE STRING "Compile with custom C++ standard version")

set(CMAKE_CXX_STANDARD ${OVERRIDE_CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

# the RPATH to be used when installing
SET(CMAKE_INSTALL_RPATH "")

# don't add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

set(QT_VERSION_MAJOR "5")
set(QT_COMPONENTS Core Network)

if (DEVELOPER_BUILD)
    list(APPEND QT_COMPONENTS DBus)
endif()

find_package(Qt5 REQUIRED COMPONENTS ${QT_COMPONENTS})
find_package(ZLIB REQUIRED)

set(server_SOURCES
    main.cpp
)

add_executable(TelegramTestServer ${server_SOURCES})
target_link_libraries(TelegramTestServer
    Qt5::Core
    Qt5::Network

    TelegramServerQt${QT_VERSION_MAJOR}
    test_keys_data
)

if (DEVELOPER_BUILD)
    add_definitions(-DDEVELOPER_BUILD)
    add_definitions(-DQT_DEPRECATED_WARNINGS)
    add_definitions(-DUSE_DBUS_NOTIFIER)

    target_link_libraries(TelegramTestServer
        Qt5::DBus
    )
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/server
    ${CMAKE_SOURCE_DIR}/tests/data
    ${CMAKE_SOURCE_DIR}/tests/utils
)
