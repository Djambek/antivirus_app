cmake_minimum_required(VERSION 3.15)
project(AntivirusSystem VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)


set(IDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/AntivirusRPC.idl)
set(ACF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/AntivirusRPC.acf)
set(IDL_HEADER ${CMAKE_CURRENT_BINARY_DIR}/AntivirusRPC_h.h)
set(IDL_SERVER ${CMAKE_CURRENT_BINARY_DIR}/AntivirusRPC_s.c)
set(IDL_CLIENT ${CMAKE_CURRENT_BINARY_DIR}/AntivirusRPC_c.c)

add_custom_command(
    OUTPUT ${IDL_HEADER} ${IDL_SERVER} ${IDL_CLIENT}
    COMMAND midl.exe /nologo /env win64 /h ${IDL_HEADER} /sstub ${IDL_SERVER} /cstub ${IDL_CLIENT} /acf ${ACF_FILE} ${IDL_FILE}
    DEPENDS ${IDL_FILE} ${ACF_FILE}
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# --- Сборка Windows-службы ---
add_executable(AntivirusService ServiceMain.cpp ${IDL_SERVER} ${IDL_HEADER})
target_compile_definitions(AntivirusService PRIVATE UNICODE _UNICODE)

target_link_libraries(AntivirusService PRIVATE Rpcrt4 Wtsapi32 Userenv Advapi32 User32)

# --- Сборка Графического приложения (TrayApp) ---
add_executable(TrayApp WIN32 main.cpp resource.rc ${IDL_CLIENT} ${IDL_HEADER})
target_compile_definitions(TrayApp PRIVATE UNICODE _UNICODE)
target_link_libraries(TrayApp PRIVATE user32 shell32 Rpcrt4 Advapi32 Wtsapi32)