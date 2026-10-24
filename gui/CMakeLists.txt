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
    src/appsettings.cpp
    src/appsettings.h
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

# English catalog shared with the Rust crates, and the application icon.
file(GLOB PO_FILES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../po/*.po)
qt_add_resources(Luks-Assistant-GUI translations
    PREFIX /po
    BASE ../po
    FILES ${PO_FILES})
qt_add_resources(Luks-Assistant-GUI icons
    PREFIX /icons
    BASE ../packaging/icons
    FILES ../packaging/icons/luks-assistant.png ../packaging/icons/luks-assistant-128.png)

target_compile_definitions(Luks-Assistant-GUI PRIVATE
    LUKS_ASSISTANT_VERSION="${PROJECT_VERSION}")
target_compile_options(Luks-Assistant-GUI PRIVATE -Wall -Wextra)
target_link_libraries(Luks-Assistant-GUI PRIVATE Qt6::Widgets)

include(GNUInstallDirs)
install(TARGETS Luks-Assistant-GUI RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
