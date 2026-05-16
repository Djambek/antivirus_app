#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <vector>
#include <string>

// ВАЖНО: Совместимость с кодом на C
extern "C" {
    #include "AntivirusRPC_h.h" 
}

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

// Функция для динамического получения пути к GUI-приложению
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

    std::wstring guiAppPath = GetGuiAppPath();
    std::wstring cmdLine = guiAppPath + L" -hidden";

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

void TerminateAllGuiProcesses() {
    for (HANDLE hProc : g_GuiProcesses) {
        TerminateProcess(hProc, 0);
        CloseHandle(hProc);
    }
    g_GuiProcesses.clear();
}

// --- RPC Сервер ---

// Реализация функций для C-кода, сгенерированного MIDL (ВАЖНО: extern "C")
extern "C" {
    void RpcStopAntivirusService(handle_t Binding) {
        OutputDebugStringW(L"RPC Stop Command Received!");
        SetEvent(g_ServiceStopEvent);
    }

    void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
    void __RPC_USER MIDL_user_free(void* p) { free(p); }
}

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
    }
}

void StopRpcServer() {
    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf(NULL, NULL, FALSE);
}

// --- Управление Службой ---

DWORD WINAPI ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
        case SERVICE_CONTROL_SESSIONCHANGE:
            if (dwEventType == WTS_SESSION_LOGON) {
                WTSSESSION_NOTIFICATION* pSessionNotification = (WTSSESSION_NOTIFICATION*)lpEventData;
                LaunchGuiInSession(pSessionNotification->dwSessionId);
            }
            return NO_ERROR;
        
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandlerEx, NULL);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE; 
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    LaunchGuiInAllActiveSessions();
    StartRpcServer();

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    TerminateAllGuiProcesses();
    StopRpcServer();

    CloseHandle(g_ServiceStopEvent);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int wmain(int argc, wchar_t* argv[]) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}
    };

    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}