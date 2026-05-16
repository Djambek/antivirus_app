#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <rpc.h>
#include "resource.h"

// Идентификаторы элементов управления (Controls ID)
#define IDC_POLL_TIMER       1001
#define IDC_EDIT_LOGIN       1002
#define IDC_EDIT_PASSWORD    1003
#define IDC_BTN_LOGIN        1004
#define IDC_EDIT_KEY         1005
#define IDC_BTN_ACTIVATE     1006
#define IDC_BTN_LOGOUT       1007
#define IDC_STATIC_INFO      1008
#define IDC_BTN_SCAN         1009 // Кнопка самого антивируса для проверки требования №11

// Переменные состояния интерфейса
bool g_IsAuthenticated = false;
bool g_HasLicense = false;
wchar_t g_Username[256] = L"";
wchar_t g_LicenseExpires[64] = L"";

// Хэндлы динамических элементов управления
HWND hEditLogin = NULL, hEditPassword = NULL, hBtnLogin = NULL;
HWND hEditKey = NULL, hBtnActivate = NULL, hBtnLogout = NULL;
HWND hStaticInfo = NULL, hBtnScan = NULL;

// ВАЖНО: Указываем компилятору C++, что этот заголовок и функции написаны на C
extern "C" {
    #include "AntivirusRPC_h.h"
    void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
    void __RPC_USER MIDL_user_free(void* p) { free(p); }
}

#pragma comment(lib, "Rpcrt4.lib")

#define WM_APP_TRAYMSG (WM_APP + 1)

HINSTANCE g_hInst;
HWND g_hWnd;
UINT g_uTaskbarRestart;
const wchar_t szTitle[] = L"Tray Application";
const wchar_t szWindowClass[] = L"TrayAppClass";
const wchar_t SERVICE_NAME[] = L"AntivirusTrayService";
const wchar_t SERVICE_EXE[] = L"AntivirusService.exe";

bool StartAntivirusService() {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            if (StartServiceW(hService, 0, NULL)) {
                while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                    if (ssp.dwCurrentState == SERVICE_RUNNING) break;
                    Sleep(500);
                }
            }
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true; 
        }
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return false;
}

bool IsParentService() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD parentPid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    bool isService = false;
    if (parentPid != 0 && Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == parentPid) {
                if (_wcsicmp(pe.szExeFile, SERVICE_EXE) == 0) {
                    isService = true;
                }
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return isService;
}

void StopServiceViaRPC() {
    RPC_WSTR szStringBinding = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;

    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"AntivirusRpcEndpoint", NULL, &szStringBinding) == RPC_S_OK) {
        if (RpcBindingFromStringBindingW(szStringBinding, &hBinding) == RPC_S_OK) {
            __try {
                RpcStopAntivirusService(hBinding);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Если служба уже не отвечает
            }
            RpcBindingFree(&hBinding);
        }
        RpcStringFreeW(&szStringBinding);
    }
}

void AddTrayIcon(HWND hwnd) {
    NOTIFYICONDATA nid = { sizeof(nid) };
    nid.hWnd = hwnd;
    nid.uID = IDI_APPICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_APP_TRAYMSG;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); 
    wcscpy_s(nid.szTip, szTitle);
    Shell_NotifyIcon(NIM_ADD, &nid);
}

void RemoveTrayIcon(HWND hwnd) {
    NOTIFYICONDATA nid = { sizeof(nid) };
    nid.hWnd = hwnd;
    nid.uID = IDI_APPICON;
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

void ShowTrayMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU hMenu = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_TRAYMENU));
    if (hMenu) {
        HMENU hSubMenu = GetSubMenu(hMenu, 0);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(hSubMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == g_uTaskbarRestart) {
        AddTrayIcon(hwnd);
        return 0;
    }

    switch (message) {
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case ID_FILE_EXIT:
        case ID_TRAY_EXIT:
            StopServiceViaRPC();
            break;
        case ID_TRAY_OPEN:
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            break;
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
        }
    } break;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0; 
    case WM_DESTROY:
        RemoveTrayIcon(hwnd);
        PostQuitMessage(0);
        break;
    case WM_APP_TRAYMSG:
        switch (lParam) {
        case WM_LBUTTONUP:
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            break;
        case WM_RBUTTONUP:
            ShowTrayMenu(hwnd);
            break;
        }
        break;
    default:
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    if (StartAntivirusService()) {
        return 0; 
    }

    if (!IsParentService()) {
        return 0; 
    }

    HANDLE hMutex = CreateMutex(NULL, TRUE, L"Global\\MyTrayAppMutex_Unique_123");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }

    g_hInst = hInstance;
    g_uTaskbarRestart = RegisterWindowMessage(L"TaskbarCreated");

    WNDCLASSEX wcex = { sizeof(WNDCLASSEX), CS_HREDRAW | CS_VREDRAW, WndProc, 0, 0, hInstance, NULL, LoadCursor(nullptr, IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), MAKEINTRESOURCE(IDR_MAINMENU), szWindowClass, NULL };
    RegisterClassEx(&wcex);

    g_hWnd = CreateWindowW(
        szWindowClass, 
        L"Antivirus Client Dashboard", // Меняем заголовок окна
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, // Отключаем растягивание и кнопку развертывания на весь экран
        CW_USEDEFAULT, 
        0, 
        400, // Ширина окна
        350, // Высота окна (лучше поставить 350-400, чтобы все созданные кнопки и текстовые поля формы входа комфортно поместились)
        nullptr, 
        nullptr, 
        hInstance, 
        nullptr
    );
    if (!g_hWnd) return FALSE;

    bool startHidden = (wcsstr(lpCmdLine, L"-hidden") != nullptr || wcsstr(lpCmdLine, L"--hidden") != nullptr);
    if (!startHidden) {
        ShowWindow(g_hWnd, nCmdShow);
        UpdateWindow(g_hWnd);
    }

    AddTrayIcon(g_hWnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CloseHandle(hMutex);
    return (int)msg.wParam;
}
void ScanFileViaRPC(const wchar_t* filePath) {
    RPC_WSTR szStringBinding = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;

    // Соединяемся по локальному протоколу ncalrpc к эндпоинту службы
    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"AntivirusRpcEndpoint", NULL, &szStringBinding) == RPC_S_OK) {
        if (RpcBindingFromStringBindingW(szStringBinding, &hBinding) == RPC_S_OK) {
            __try {
                // Вызываем функцию RPC. Логика проверки лицензии выполнится внутри службы.
                RpcScanFile(hBinding, filePath);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Обработка ошибки, если служба не отвечает или упала
                OutputDebugStringW(L"Ошибка RPC при попытке сканирования.");
            }
            RpcBindingFree(&hBinding);
        }
        RpcStringFreeW(&szStringBinding);
    }
}

void UpdateInterfaceState(HWND hwnd) {
    // 1. Сценарий: Пользователь не аутентифицирован (Форма входа)
    if (!g_IsAuthenticated) {
        // Показываем элементы входа
        ShowWindow(hEditLogin, SW_SHOW);
        ShowWindow(hEditPassword, SW_SHOW);
        ShowWindow(hBtnLogin, SW_SHOW);
        
        // Скрываем всё остальное
        ShowWindow(hEditKey, SW_HIDE);
        ShowWindow(hBtnActivate, SW_HIDE);
        ShowWindow(hBtnLogout, SW_HIDE);
        ShowWindow(hBtnScan, SW_HIDE); // Блокируем/прячем антивирус
        
        SetWindowTextW(hStaticInfo, L"Для использования антивируса необходимо войти в систему:");
    }
    // 2. Сценарий: Вошел, но нет лицензии (Форма активации)
    else if (g_IsAuthenticated && !g_HasLicense) {
        // Скрываем элементы входа
        ShowWindow(hEditLogin, SW_HIDE);
        ShowWindow(hEditPassword, SW_HIDE);
        ShowWindow(hBtnLogin, SW_HIDE);
        
        // Показываем элементы активации и выхода
        ShowWindow(hEditKey, SW_SHOW);
        ShowWindow(hBtnActivate, SW_SHOW);
        ShowWindow(hBtnLogout, SW_SHOW);
        ShowWindow(hBtnScan, SW_HIDE); // Блокируем/прячем антивирус
        
        std::wstring info = L"Пользователь: " + std::wstring(g_Username) + L"\nСтатус: Лицензия не найдена. Введите код активации:";
        SetWindowTextW(hStaticInfo, info.c_str());
    }
    // 3. Сценарий: Всё успешно (Антивирус разблокирован)
    else if (g_IsAuthenticated && g_HasLicense) {
        // Скрываем все формы ввода
        ShowWindow(hEditLogin, SW_HIDE);
        ShowWindow(hEditPassword, SW_HIDE);
        ShowWindow(hBtnLogin, SW_HIDE);
        ShowWindow(hEditKey, SW_HIDE);
        ShowWindow(hBtnActivate, SW_HIDE);
        
        // Показываем кнопку выхода и функционал антивируса
        ShowWindow(hBtnLogout, SW_SHOW);
        ShowWindow(hBtnScan, SW_SHOW); // РАЗБЛОКИРОВАНО
        
        std::wstring info = L"Пользователь: " + std::wstring(g_Username) + L"\nЛицензия активна до: " + std::wstring(g_LicenseExpires);
        SetWindowTextW(hStaticInfo, info.c_str());
    }
}

void PollServiceStatus(HWND hwnd) {
    RPC_WSTR szStringBinding = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;
    
    bool auth = false;
    bool lic = false;
    wchar_t user[256] = L"";
    wchar_t expires[64] = L"";

    if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"AntivirusRpcEndpoint", NULL, &szStringBinding) == RPC_S_OK) {
        if (RpcBindingFromStringBindingW(szStringBinding, &hBinding) == RPC_S_OK) {
            __try {
                // Вызываем добавленный ранее RPC метод
                RpcGetStatus(hBinding, &auth, user, &lic, expires);
                
                // Если состояние изменилось — обновляем интерфейс
                if (auth != g_IsAuthenticated || lic != g_HasLicense || wcscmp(user, g_Username) != 0) {
                    g_IsAuthenticated = auth;
                    g_HasLicense = lic;
                    wcscpy_s(g_Username, user);
                    wcscpy_s(g_LicenseExpires, expires);
                    
                    UpdateInterfaceState(hwnd);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Если служба упала или недоступна, блокируем интерфейс
                if (g_IsAuthenticated || g_HasLicense) {
                    g_IsAuthenticated = false;
                    g_HasLicense = false;
                    UpdateInterfaceState(hwnd);
                }
            }
            RpcBindingFree(&hBinding);
        }
        RpcStringFreeW(&szStringBinding);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Создаем текстовое поле для вывода информации
        hStaticInfo = CreateWindowW(L"STATIC", L"Проверка связи со службой...", WS_CHILD | WS_VISIBLE | SS_LEFT, 
                                    20, 20, 350, 40, hwnd, (HMENU)IDC_STATIC_INFO, NULL, NULL);

        // --- Элементы формы АУТЕНТИФИКАЦИИ ---
        hEditLogin = CreateWindowW(L"EDIT", L"admin@mtuci.ru", WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 
                                   20, 70, 200, 25, hwnd, (HMENU)IDC_EDIT_LOGIN, NULL, NULL);
        hEditPassword = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 
                                      20, 105, 200, 25, hwnd, (HMENU)IDC_EDIT_PASSWORD, NULL, NULL);
        hBtnLogin = CreateWindowW(L"BUTTON", L"Войти", WS_CHILD | BS_PUSHBUTTON, 
                                  20, 140, 100, 30, hwnd, (HMENU)IDC_BTN_LOGIN, NULL, NULL);

        // --- Элементы формы АКТИВАЦИИ ---
        hEditKey = CreateWindowW(L"EDIT", L"XXXX-XXXX-XXXX-XXXX", WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 
                                 20, 70, 200, 25, hwnd, (HMENU)IDC_EDIT_KEY, NULL, NULL);
        hBtnActivate = CreateWindowW(L"BUTTON", L"Активировать", WS_CHILD | BS_PUSHBUTTON, 
                                     20, 105, 120, 30, hwnd, (HMENU)IDC_BTN_ACTIVATE, NULL, NULL);

        // --- Общие элементы управления ---
        hBtnLogout = CreateWindowW(L"BUTTON", L"Выйти из аккаунта", WS_CHILD | BS_PUSHBUTTON, 
                                   20, 200, 150, 30, hwnd, (HMENU)IDC_BTN_LOGOUT, NULL, NULL);
        
        // Функциональная кнопка самого антивируса (будет скрыта при отсутствии лицензии)
        hBtnScan = CreateWindowW(L"BUTTON", L"Запустить сканирование", WS_CHILD | BS_PUSHBUTTON, 
                                 20, 70, 200, 40, hwnd, (HMENU)IDC_BTN_SCAN, NULL, NULL);

        // Установка шрифта для красивого отображения
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEAN_TEXT_QUALITY, VARIABLE_PITCH, L"Segoe UI");
        SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, TRUE);
        EnumChildWindows(hwnd, [](HWND hChild, LPARAM lp) -> BOOL { SendMessage(hChild, WM_SETFONT, lp, TRUE); return TRUE; }, (LPARAM)hFont);

        // Требование №1 и №8: Сразу при запуске опрашиваем службу и запускаем таймер (каждые 3 секунды)
        PollServiceStatus(hwnd);
        SetTimer(hwnd, IDC_POLL_TIMER, 3000, NULL);
        break;
    }

    case WM_TIMER:
        if (wParam == IDC_POLL_TIMER) {
            PollServiceStatus(hwnd); // Требование №8 (Подписка/опрос состояния лицензии)
        }
        break;

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        
        RPC_WSTR szStringBinding = NULL;
        RPC_BINDING_HANDLE hBinding = NULL;
        
        // Подключаемся к RPC для отправки команд службы
        if (wmId == IDC_BTN_LOGIN || wmId == IDC_BTN_ACTIVATE || wmId == IDC_BTN_LOGOUT || wmId == IDC_BTN_SCAN) {
            if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"AntivirusRpcEndpoint", NULL, &szStringBinding) != RPC_S_OK) break;
            if (RpcBindingFromStringBindingW(szStringBinding, &hBinding) != RPC_S_OK) { RpcStringFreeW(&szStringBinding); break; }
        }

        switch (wmId) {
        case IDC_BTN_LOGIN: {
            wchar_t mail[128], pass[128], errorMsg[256] = L"";
            GetWindowTextW(hEditLogin, mail, 128);
            GetWindowTextW(hEditPassword, pass, 128);

            __try {
                // Вызываем RpcLogin в службе
                if (RpcLogin(hBinding, mail, pass, errorMsg)) {
                    PollServiceStatus(hwnd); // В случае успеха мгновенно обновляем экран
                } else {
                    // Требование №3: Ошибка и повторный ввод
                    MessageBoxW(hwnd, errorMsg, L"Ошибка авторизации", MB_OK | MB_ICONERROR);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                MessageBoxW(hwnd, L"Служба не отвечает.", L"Ошибка RPC", MB_OK | MB_ICONERROR);
            }
            break;
        }

        case IDC_BTN_ACTIVATE: {
            wchar_t key[128], errorMsg[256] = L"";
            GetWindowTextW(hEditKey, key, 128);

            __try {
                if (RpcActivateProduct(hBinding, key, errorMsg)) {
                    PollServiceStatus(hwnd); // Успешная активация -> разблокировка функционала
                } else {
                    // Требование №6: Ошибка активации -> повторный ввод
                    MessageBoxW(hwnd, errorMsg, L"Ошибка лицензии", MB_OK | MB_ICONERROR);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                MessageBoxW(hwnd, L"Ошибка соединения при активации.", L"Ошибка RPC", MB_OK | MB_ICONERROR);
            }
            break;
        }

        case IDC_BTN_LOGOUT:
            __try {
                RpcLogout(hBinding); // Вызов выхода
                PollServiceStatus(hwnd);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            break;

        case IDC_BTN_SCAN:
            __try {
                // Пример вызова вашей функции сканирования (Проверит лицензию внутри Service)
                RpcScanFile(hBinding, L"C:\\test_file.exe");
                MessageBoxW(hwnd, L"Файл отправлен на сканирование!", L"Антивирус", MB_OK | MB_ICONINFORMATION);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            break;
        }

        if (hBinding) RpcBindingFree(&hBinding);
        if (szStringBinding) RpcStringFreeW(&szStringBinding);
        break;
    }

    // Обработка Tray-иконки и закрытия окна (оставляем вашу логику из prak-2)
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        KillTimer(hwnd, IDC_POLL_TIMER);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}
