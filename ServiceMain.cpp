#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <vector>
#include <string>
#include <iostream>

// Подключаем заголовок, сгенерированный MIDL
#include "AntivirusRPC_h.h" 

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Rpcrt4.lib")

// Глобальные переменные службы
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

// Список запущенных процессов GUI
std::vector<HANDLE> g_GuiProcesses;

const wchar_t* SERVICE_NAME = L"AntivirusTrayService";
const RPC_WSTR RPC_ENDPOINT = (RPC_WSTR)L"AntivirusRpcEndpoint";

// Функция для динамического получения пути к GUI-приложению (вместо хардкода)
std::wstring GetGuiAppPath() {
    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameW(NULL, buffer, MAX_PATH) != 0) {
        std::wstring servicePath(buffer);
        size_t pos = servicePath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            return servicePath.substr(0, pos + 1) + L"TrayApp.exe";
        }
    }
    return L"TrayApp.exe"; 
}

// --- Функции управления процессами в сессиях ---

// Запуск GUI в конкретной сессии
void LaunchGuiInSession(DWORD sessionId) {
    HANDLE hUserToken = NULL;
    HANDLE hDupToken = NULL;
    LPVOID pEnv = NULL;

    if (!WTSQueryUserToken(sessionId, &hUserToken)) {
        return;
    }

    if (!DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken)) {
        CloseHandle(hUserToken);
        return;
    }

    if (!CreateEnvironmentBlock(&pEnv, hDupToken, FALSE)) {
        CloseHandle(hDupToken);
        CloseHandle(hUserToken);
        return;
    }

    STARTUPINFOEXW siex;
    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    siex.StartupInfo.lpDesktop = (LPWSTR)L"winsta0\\default"; 
    siex.StartupInfo.wShowWindow = SW_HIDE; 
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Получаем динамический путь и формируем аргументы
    std::wstring guiAppPath = GetGuiAppPath();
    std::wstring cmdLine = guiAppPath + L" -hidden";

    // ИСПРАВЛЕНИЕ ОШИБКИ C2440: используем .c_str() для конвертации std::wstring в const wchar_t*
    BOOL bResult = CreateProcessAsUserW(
        hDupToken,
        guiAppPath.c_str(), 
        &cmdLine[0],
        NULL,
        NULL,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
        pEnv,
        NULL,
        &siex.StartupInfo,
        &pi
    );

    if (bResult) {
        g_GuiProcesses.push_back(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DestroyEnvironmentBlock(pEnv);
    CloseHandle(hDupToken);
    CloseHandle(hUserToken);
}

// Запуск GUI во всех активных сессиях (кроме нулевой)
void LaunchGuiInAllActiveSessions() {
    PWTS_SESSION_INFOW pSessionInfo = NULL;
    DWORD count = 0;

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count)) {
        for (DWORD i = 0; i < count; i++) {
            if (pSessionInfo[i].SessionId != 0 && pSessionInfo[i].State == WTSActive) {
                LaunchGuiInSession(pSessionInfo[i].SessionId);
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
}

// Завершение всех запущенных GUI процессов
void TerminateAllGuiProcesses() {
    for (HANDLE hProc : g_GuiProcesses) {
        TerminateProcess(hProc, 0);
        CloseHandle(hProc);
    }
    g_GuiProcesses.clear();
}

// --- RPC Сервер ---

// Реализация функции остановки, которую вызывает клиент
void RpcStopAntivirusService(handle_t Binding) {
    OutputDebugStringW(L"RPC Stop Command Received!");
    SetEvent(g_ServiceStopEvent);
}

// Функции аллокации памяти для RPC
void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER MIDL_user_free(void* p) { free(p); }

void StartRpcServer() {
    RPC_STATUS status;
    status = RpcServerUseProtseqEpW(
        (RPC_WSTR)L"ncalrpc",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        RPC_ENDPOINT,
        NULL
    );

    if (status == RPC_S_OK) {
        status = RpcServerRegisterIf(AntivirusRPC_v1_0_s_ifspec, NULL, NULL);
        if (status == RPC_S_OK) {
            RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 1);
        }