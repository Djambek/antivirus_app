#include <windows.h>
#include <wchar.h>
#include "resource.h"

#define WM_APP_TRAYMSG (WM_APP + 1)

// Глобальные переменные
HINSTANCE g_hInst;
HWND g_hWnd;
UINT g_uTaskbarRestart;
const wchar_t szTitle[] = L"Tray Application";
const wchar_t szWindowClass[] = L"TrayAppClass";

// Функции для работы с треем
void AddTrayIcon(HWND hwnd) {
    NOTIFYICONDATA nid = { sizeof(nid) };
    nid.hWnd = hwnd;
    nid.uID = IDI_APPICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_APP_TRAYMSG;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); // Замените NULL на g_hInst, если добавите app.ico
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
        // SetForegroundWindow нужен, чтобы меню закрывалось при клике мимо него
        SetForegroundWindow(hwnd);
        TrackPopupMenu(hSubMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
    }
}

// Обработчик сообщений окна
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // Восстановление иконки при падении/перезапуске explorer.exe
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
            RemoveTrayIcon(hwnd);
            PostQuitMessage(0); // Полное завершение работы
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
        // При закрытии крестиком просто прячем окно, работа продолжается
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
    // 10. Защита от повторного запуска (Мьютекс)
    HANDLE hMutex = CreateMutex(NULL, TRUE, L"Global\\MyTrayAppMutex_Unique_123");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0; // Молча завершаем работу до добавления иконки
    }

    g_hInst = hInstance;
    g_uTaskbarRestart = RegisterWindowMessage(L"TaskbarCreated");

    WNDCLASSEX wcex = { sizeof(WNDCLASSEX) };
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCE(IDR_MAINMENU);
    wcex.lpszClassName = szWindowClass;
    RegisterClassEx(&wcex);

    g_hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 400, 300, nullptr, nullptr, hInstance, nullptr);

    if (!g_hWnd) return FALSE;

    // 7. Поддержка запуска в скрытом режиме (через аргумент -hidden)
    bool startHidden = (wcsstr(lpCmdLine, L"-hidden") != nullptr || wcsstr(lpCmdLine, L"--hidden") != nullptr);
    
    if (!startHidden) {
        ShowWindow(g_hWnd, nCmdShow);
        UpdateWindow(g_hWnd);
    }

    // Добавляем иконку в трей при запуске
    AddTrayIcon(g_hWnd);

    // Цикл обработки сообщений
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CloseHandle(hMutex);
    return (int)msg.wParam;
}