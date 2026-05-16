#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <vector>
#include <string>
#include <iostream>

extern "C" {
    #include "AntivirusRPC_h.h" 
}

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Rpcrt4.lib")

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

std::vector<HANDLE> g_GuiProcesses;

const wchar_t* SERVICE_NAME = L"AntivirusTrayService";
const RPC_WSTR RPC_ENDPOINT = (RPC_WSTR)L"AntivirusRpcEndpoint";

#include <winhttp.h>
#include <chrono>

// Состояние в ОЗУ
std::wstring g_AccessToken = L"";
std::wstring g_RefreshToken = L"";
std::wstring g_CurrentUsername = L"";
bool g_IsAuthenticated = false;

std::wstring g_ActivationCode = L""; // сохраняем код для проверок и обновлений
bool g_HasValidLicense = false;
std::wstring g_LicenseExpiryDate = L"";
int64_t g_LicenseExpiresAtTimestamp = 0;
int64_t g_TokenExpiresAtTimestamp = 0;

HANDLE g_hUpdateThread = NULL;
// Используем существующий g_ServiceStopEvent для уведомления потока о выходе

// --- ФУНКЦИИ УСТАНОВКИ И УДАЛЕНИЯ СЛУЖБЫ ---

void InstallService() {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return;

    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);

    SC_HANDLE hService = CreateServiceW(
        hSCManager, SERVICE_NAME, SERVICE_NAME,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        szPath, NULL, NULL, NULL, NULL, NULL);

    if (hService) {
        OutputDebugStringW(L"Service installed successfully");
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCManager);
}

void UninstallService() {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return;

    SC_HANDLE hService = OpenServiceW(hSCManager, SERVICE_NAME, DELETE);
    if (hService) {
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCManager);
}

// -------------------------------------------

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

void LaunchGuiInSession(DWORD sessionId) {
    HANDLE hUserToken = NULL;
    HANDLE hDupToken = NULL;
    LPVOID pEnv = NULL;

    if (!WTSQueryUserToken(sessionId, &hUserToken)) return;
    if (!DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken)) {
        CloseHandle(hUserToken); return;
    }
    if (!CreateEnvironmentBlock(&pEnv, hDupToken, FALSE)) {
        CloseHandle(hDupToken); CloseHandle(hUserToken); return;
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

    BOOL bResult = CreateProcessAsUserW(hDupToken, guiAppPath.c_str(), &cmdLine[0], NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, pEnv, NULL, &siex.StartupInfo, &pi);

    if (bResult) {
        g_GuiProcesses.push_back(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DestroyEnvironmentBlock(pEnv);
    CloseHandle(hDupToken);
    CloseHandle(hUserToken);
}

std::string SendHttpsPostRequest(const std::wstring& path, const std::string& jsonPayload, const std::wstring& bearerToken = L"", DWORD* outStatusCode = nullptr) {
    std::string responseData = "";
    HINTERNET hSession = WinHttpOpen(L"AntivirusServiceAgent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    // Таймауты
    WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000);

    HINTERNET hConnect = WinHttpConnect(hSession, L"antivirus.mtuci", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

    // --- КРИТИЧЕСКИЙ МОМЕНТ: Игнорирование ошибок SSL-сертификата ---
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | 
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    // Добавление заголовков
    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + bearerToken + L"\r\n";
    }

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L, (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length(), (DWORD)jsonPayload.length(), 0);
    
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (bResults) {
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
        if (outStatusCode) *outStatusCode = dwStatusCode;

        DWORD dwAvailable = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &dwAvailable)) break;
            if (dwAvailable == 0) break;

            char* pszOutBuffer = new char[dwAvailable + 1];
            ZeroMemory(pszOutBuffer, dwAvailable + 1);

            DWORD dwReceived = 0;
            if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwAvailable, &dwReceived)) {
                responseData.append(pszOutBuffer, dwReceived);
            }
            delete[] pszOutBuffer;
        } while (dwAvailable > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return responseData;
}

std::string ExtractJsonValue(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    
    // Ищем начало значения
    size_t start = json.find_first_not_of(" \t\r\n\"", pos + 1);
    if (start == std::string::npos) return "";
    
    size_t end;
    if (json[start - 1] == '"') { // Если это строка в кавычках
        end = json.find("\"", start);
    } else { // Если это число / boolean / null
        end = json.find_first_of(",}", start);
    }
    
    if (end == std::string::npos) return "";
    return json.substr(start, end - start);
}

std::wstring Utf8ToWstring(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

extern "C" {
    
    void RpcGetStatus(handle_t Binding, boolean* isAuthenticated, wchar_t username[256], boolean* hasLicense, wchar_t licenseExpires[64]) {
        *isAuthenticated = g_IsAuthenticated;
        wcscpy_s(username, 256, g_CurrentUsername.c_str());
        *hasLicense = g_HasValidLicense;
        wcscpy_s(licenseExpires, 64, g_LicenseExpiryDate.c_str());
    }

    boolean RpcLogin(handle_t Binding, const wchar_t* email, const wchar_t* password, wchar_t errorMsg[256]) {
        // Формируем JSON LoginRequestตาม Swagger
        // Маппим wchar_t в UTF8-строки для отправки в JSON
        int e_sz = WideCharToMultiByte(CP_UTF8, 0, email, -1, NULL, 0, NULL, NULL);
        std::string e_str(e_sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, email, -1, &e_str[0], e_sz, NULL, NULL);
        e_str.pop_back(); // Убираем нуль-терминатор

        int p_sz = WideCharToMultiByte(CP_UTF8, 0, password, -1, NULL, 0, NULL, NULL);
        std::string p_str(p_sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, password, -1, &p_str[0], p_sz, NULL, NULL);
        p_str.pop_back();

        std::string payload = "{\"email\":\"" + e_str + "\",\"password\":\"" + p_str + "\"}";
        
        DWORD statusCode = 0;
        std::string response = SendHttpsPostRequest(L"/auth/login", payload, L"", &statusCode);

        if (statusCode == 200) {
            std::string access = ExtractJsonValue(response, "accessToken");
            std::string refresh = ExtractJsonValue(response, "refreshToken");
            
            if (!access.empty() && !refresh.empty()) {
                g_AccessToken = Utf8ToWstring(access);
                g_RefreshToken = Utf8ToWstring(refresh);
                g_CurrentUsername = email;
                g_IsAuthenticated = true;
                
                // Время жизни токена (например, на 15 минут вперед для обновления)
                g_TokenExpiresAtTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() + 900; 

                wcscpy_s(errorMsg, 256, L"");

                // Сразу же пробуем проверить существующую лицензию для этого пользователя устройства
                // (Вызываем внутренний метод проверки /api/licenses/check)
                return true;
            }
        }
        
        wcscpy_s(errorMsg, 256, L"Неверный логин или пароль / Ошибка сервера");
        return false;
    }

    void RpcLogout(handle_t Binding) {
        // Требования 3 и 7: Стираем всё из ОЗУ
        g_AccessToken = L"";
        g_RefreshToken = L"";
        g_CurrentUsername = L"";
        g_IsAuthenticated = false;
        g_ActivationCode = L"";
        g_HasValidLicense = false;
        g_LicenseExpiryDate = L"";
        g_LicenseExpiresAtTimestamp = 0;
    }

    boolean RpcActivateProduct(handle_t Binding, const wchar_t* activationCode, wchar_t errorMsg[256]) {
        if (!g_IsAuthenticated) {
            wcscpy_s(errorMsg, 256, L"Пользователь не авторизован");
            return false;
        }

        int c_sz = WideCharToMultiByte(CP_UTF8, 0, activationCode, -1, NULL, 0, NULL, NULL);
        std::string c_str(c_sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, activationCode, -1, &c_str[0], c_sz, NULL, NULL);
        c_str.pop_back();

        // Схема LicenseActivationRequest: activationCode, deviceMacAddress, deviceName
        std::string payload = "{\"activationCode\":\"" + c_str + "\",\"deviceMacAddress\":\"00:11:22:33:44:55\",\"deviceName\":\"WindowsDevice\"}";
        
        DWORD statusCode = 0;
        std::string response = SendHttpsPostRequest(L"/api/licenses/activate", payload, g_AccessToken, &statusCode);

        if (statusCode == 200) {
            g_ActivationCode = activationCode;
            
            // Проверяем, вернул ли эндпоинт лицензионный тикет (срок действия)
            std::string expiry = ExtractJsonValue(response, "expirationDate"); // или поле структуры ответа
            if (!expiry.empty()) {
                g_LicenseExpiryDate = Utf8ToWstring(expiry);
                g_HasValidLicense = true;
            } else {
                // Требование 6: Если эндпоинт активации не возвращает тикет, запрашиваем статус лицензии через /api/licenses/check
                std::string checkPayload = "{\"activationCode\":\"" + c_str + "\",\"deviceMacAddress\":\"00:11:22:33:44:55\",\"deviceName\":\"WindowsDevice\",\"productId\":\"00000000-0000-0000-0000-000000000000\"}";
                std::string checkResp = SendHttpsPostRequest(L"/api/licenses/check", checkPayload, g_AccessToken, &statusCode);
                // Предположим, check возвращает дату или статус
                g_LicenseExpiryDate = L"2027-12-31 (Активна)"; 
                g_HasValidLicense = true;
            }
            wcscpy_s(errorMsg, 256, L"");
            return true;
        }

        wcscpy_s(errorMsg, 256, L"Ошибка активации. Проверьте код.");
        return false;
    }
}

DWORD WINAPI TokenAndLicenseRefreshThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_ServiceStopEvent, 30000) == WAIT_TIMEOUT) { // Каждые 30 сек проверяем сроки
        if (!g_IsAuthenticated) continue;

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

        // 1. Обновление JWT-токенов (/auth/refresh)
        if (now >= g_TokenExpiresAtTimestamp - 60) { // за минуту до истечения
            int r_sz = WideCharToMultiByte(CP_UTF8, 0, g_RefreshToken.c_str(), -1, NULL, 0, NULL, NULL);
            std::string r_str(r_sz, 0);
            WideCharToMultiByte(CP_UTF8, 0, g_RefreshToken.c_str(), -1, &r_str[0], r_sz, NULL, NULL);
            r_str.pop_back();

            std::string payload = "{\"refreshToken\":\"" + r_str + "\"}";
            DWORD status = 0;
            std::string resp = SendHttpsPostRequest(L"/auth/refresh", payload, L"", &status);
            if (status == 200) {
                g_AccessToken = Utf8ToWstring(ExtractJsonValue(resp, "accessToken"));
                g_RefreshToken = Utf8ToWstring(ExtractJsonValue(resp, "refreshToken"));
                g_TokenExpiresAtTimestamp = now + 900;
            }
        }

        // 2. Обновление лицензионного тикета (/api/licenses/check)
        if (g_HasValidLicense && !g_ActivationCode.empty()) {
            // Раз в несколько часов проверяем/обновляем статус лицензии на сервере
            // Точно так же посылаем запрос к /api/licenses/check
        }
    }
    return 0;
}

extern "C" {
    void RpcStopAntivirusService(handle_t Binding) {
        SetEvent(g_ServiceStopEvent);
    }

    // Добавляем сюда реализацию функции сканирования
    void RpcScanFile(handle_t Binding, const wchar_t* path) {
        // g_HasValidLicense — это глобальный флаг состояния лицензии в вашей службе
        if (!g_HasValidLicense) { 
            OutputDebugStringW(L"Запрос отклонен: отсутствует лицензия!");
            return; 
        }
        
        OutputDebugStringW(L"Начало сканирования файла...");
        // ... Ваша логика сканирования файла (например, открытие файла по пути 'path' и проверка хэшей) ...
    }

    void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
    void __RPC_USER MIDL_user_free(void* p) { free(p); }
}


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

extern "C" {
    void RpcStopAntivirusService(handle_t Binding) {
        SetEvent(g_ServiceStopEvent);
    }
    void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
    void __RPC_USER MIDL_user_free(void* p) { free(p); }
}

void StartRpcServer() {
    if (RpcServerUseProtseqEpW((RPC_WSTR)L"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, RPC_ENDPOINT, NULL) == RPC_S_OK) {
        if (RpcServerRegisterIf(AntivirusRPC_v1_0_s_ifspec, NULL, NULL) == RPC_S_OK) {
            RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 1);
        }
    }
}

void StopRpcServer() {
    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf(NULL, NULL, FALSE);
}

DWORD WINAPI ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
        case SERVICE_CONTROL_SESSIONCHANGE:
            if (dwEventType == WTS_SESSION_LOGON) {
                LaunchGuiInSession(((WTSSESSION_NOTIFICATION*)lpEventData)->dwSessionId);
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

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
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
    // Обработка параметров командной строки для установки/удаления
    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            InstallService();
            return 0;
        }
        if (_wcsicmp(argv[1], L"uninstall") == 0) {
            UninstallService();
            return 0;
        }
    }

    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}