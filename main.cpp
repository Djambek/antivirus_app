#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <rpc.h>
#include "resource.h"

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

    g_hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 400, 300, nullptr, nullptr, hInstance, nullptr);
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