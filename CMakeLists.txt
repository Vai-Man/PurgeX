cmake_minimum_required(VERSION 3.16)
project(PurgeX VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets PrintSupport)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets PrintSupport)
find_package(OpenSSL REQUIRED)

add_executable(PurgeX WIN32
    main.cpp
    resources.qrc
    core/WipeEngine.cpp core/WipeEngine.h
    core/AuditLog.cpp core/AuditLog.h
    core/AppPaths.h
    ui/MainWindow.cpp ui/MainWindow.h
    ui/ForensicWidget.cpp ui/ForensicWidget.h
    ui/AuditWidget.cpp ui/AuditWidget.h
    cli/CLIManager.cpp cli/CLIManager.h
    cert/CertManager.cpp cert/CertManager.h
    cert/qrcodegen.cpp cert/qrcodegen.hpp
    forensics/ForensicEngine.cpp forensics/ForensicEngine.h forensics/FileSignatures.h
)

target_include_directories(PurgeX PRIVATE core ui cli cert forensics)
target_link_libraries(PurgeX PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets Qt${QT_VERSION_MAJOR}::PrintSupport OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(PurgeX PRIVATE crypt32 ws2_32)
endif()
