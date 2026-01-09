#include <windows.h>
#include <iostream>

int main() {
    DWORD pid;
    std::cout << "PID: ";
    std::cin >> pid;

    HANDLE hProc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        pid
    );

    if (!hProc) {
        std::cerr << "OpenProcess failed\n";
        return 1;
    }

    while (true) {
        uintptr_t address; // 0x209e6005224
        std::cout << "Address (hex): ";
        std::cin >> std::hex >> address >> std::dec;

        int newValue;
        std::cout << "new value (decimal): ";
        std::cin >> newValue;

        SIZE_T written;
        WINBOOL status = WriteProcessMemory(
            hProc,
            reinterpret_cast<void *>(address),
            &newValue,
            sizeof(newValue),
            &written
        );
        if (!status) {
            std::cerr << "\n(ERROR): Failed to write to address (0x" << std::hex << address << std::dec << ")" <<
                    std::endl;
        }
    }

    CloseHandle(hProc);
}