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

#include <string>
#include <windows.h>

// Функция для динамического получения пути к GUI-приложению
std::wstring GetGuiAppPath() {
    wchar_t buffer[MAX_PATH];
    // Получаем полный путь к исполняемому файлу текущего процесса (Службы)
    if (GetModuleFileNameW(NULL, buffer, MAX_PATH) != 0) {
        std::wstring servicePath(buffer);
        // Ищем последний слэш, чтобы отделить директорию от имени файла
        size_t pos = servicePath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            // Берем путь до директории и приклеиваем имя вашего GUI-приложения
            return servicePath.substr(0, pos + 1) + L"TrayApp.exe";
        }
    }
    // Фолбэк, если что-то пошло не так (попытка запуска из рабочей директории)
    return L"TrayApp.exe"; 
}

const wchar_t* SERVICE_NAME = L"AntivirusTrayService";
const wchar_t* GUI_APP_PATH = GetGuiAppPath();
const RPC_WSTR RPC_ENDPOINT = (RPC_WSTR)L"AntivirusRpcEndpoint";

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
    siex.StartupInfo.lpDesktop = (LPWSTR)L"winsta0\\default"; // Интерактивный рабочий стол
    siex.StartupInfo.wShowWindow = SW_HIDE; // Требование: главное окно скрыто
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::wstring cmdLine = std::wstring(GUI_APP_PATH) + L" -hidden";

    // Требование 3 (Доп): Здесь можно настроить SECURITY_ATTRIBUTES для pi.hProcess,
    // чтобы запретить закрытие процесса обычным пользователям.

    BOOL bResult = CreateProcessAsUserW(
        hDupToken,
        GUI_APP_PATH,
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
        // Сохраняем HANDLE процесса для последующего завершения
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
    // Доп. Требование 1: Запрос подтверждения на Secure Desktop можно реализовать здесь.
    // Пример: WTSSendMessage() текущему пользователю перед выполнением остановки.

    OutputDebugStringW(L"RPC Stop Command Received!");

    // Уведомляем службу об остановке
    SetEvent(g_ServiceStopEvent);
}

// Функции аллокации памяти для RPC (обязательны)
void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
void __RPC_USER MIDL_user_free(void* p) { free(p); }

void StartRpcServer() {
    // Требование 4: Транспорт ALPC (ncalrpc)
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
            // Начинаем слушать RPC вызовы (асинхронно, не блокируя поток)
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
            // Требование 2: Отслеживание входа новых пользователей
            if (dwEventType == WTS_SESSION_LOGON) {
                WTSSESSION_NOTIFICATION* pSessionNotification = (WTSSESSION_NOTIFICATION*)lpEventData;
                LaunchGuiInSession(pSessionNotification->dwSessionId);
            }
            return NO_ERROR;
        
        // ВАЖНО: Мы НЕ обрабатываем SERVICE_CONTROL_STOP и SERVICE_CONTROL_SHUTDOWN (Требование 3)
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
    // Требование 3: Отключаем обработку сигналов Stop и Shutdown
    // Флаг SERVICE_ACCEPT_SESSIONCHANGE нужен для отслеживания входов
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

    // Требование 1: Запуск GUI во всех сессиях при старте
    LaunchGuiInAllActiveSessions();

    // Запуск RPC Сервера (Требование 4, 5)
    StartRpcServer();

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Служба работает до тех пор, пока RPC клиент не вызовет RpcStopAntivirusService (Требование 4)
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    // --- Остановка службы ---
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Требование 6: При остановке завершаем все GUI
    TerminateAllGuiProcesses();
    StopRpcServer();

    CloseHandle(g_ServiceStopEvent);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int wmain(int argc, wchar_t* argv[]) {
    // Здесь можно реализовать Доп. Требование 2 (настройка DACL процесса службы)
    
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}
    };

    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}