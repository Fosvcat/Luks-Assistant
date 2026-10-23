cmake_minimum_required(VERSION 3.16)

# Same version as the Rust workspace.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../Cargo.toml" _version_line REGEX "^version = ")
string(REGEX REPLACE "^version = \"([^\"]+)\".*" "\\1" LA_VERSION "${_version_line}")
project(Luks-Assistant-GUI VERSION ${LA_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS src)

find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)

add_executable(Luks-Assistant-GUI
    src/main.cpp
    src/helperclient.cpp
    src/helperclient.h
    src/mainwindow.cpp
    src/mainwindow.h
    src/mainwindow.ui
    src/formdialog.cpp
    src/formdialog.h
    src/dialogs.cpp
    src/dialogs.h
)

target_compile_definitions(Luks-Assistant-GUI PRIVATE
    LUKS_ASSISTANT_VERSION="${PROJECT_VERSION}")
target_compile_options(Luks-Assistant-GUI PRIVATE -Wall -Wextra)
target_link_libraries(Luks-Assistant-GUI PRIVATE Qt6::Widgets)

include(GNUInstallDirs)
install(TARGETS Luks-Assistant-GUI RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
