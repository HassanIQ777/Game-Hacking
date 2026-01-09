#include <cstdint>
#include <iostream>
#include <windows.h>
#include <vector>

int terminateProgram() {
    std::cin.get();
    return -1;
}

DWORD nextInt(const std::string &msg = "") {
    std::cout << msg;
    DWORD value;
    std::cin >> value;
    return value;
}

void memoryDump(const std::vector<uintptr_t> &addresses) {
    for (const uintptr_t addr: addresses) {
        // int value = *reinterpret_cast<int *>(addr);
        // std::cout << "0x" << std::hex << addr << " = " << value << "\n";
        std::cout << "0x" << std::hex << addr << std::endl;
    }
}

void refineScan(const HANDLE hProcess,
                int target,
                std::vector<uintptr_t> &candidates) {
    std::vector<uintptr_t> narrowed;

    for (uintptr_t addr: candidates) {
        int value;
        SIZE_T bytesRead;

        if (ReadProcessMemory(hProcess,
                              reinterpret_cast<LPCVOID>(addr),
                              &value,
                              sizeof(value),
                              &bytesRead)
            && bytesRead == sizeof(value)
            && value == target) {
            narrowed.push_back(addr);
        }
    }

    candidates.swap(narrowed);
}

int main() {
    const DWORD pid = nextInt("PID: ");
    std::cout << "Attempting to open the process with PID (" << pid << ")..." << std::endl;

    HANDLE handleProcess = OpenProcess(
        PROCESS_ALL_ACCESS, /* request full access */
        FALSE,
        pid);
    if (!handleProcess) {
        std::cerr << "(ERROR): Unable to get the process handle. Exiting." << std::endl;
        return terminateProgram();
    }
    std::cout << "Successfully opened the process with PID (" << pid << ")" << std::endl;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    std::vector<uintptr_t> candidates;
    int target;
    std::cout << "First scan value: ";
    std::cin >> target;

    while (VirtualQueryEx(handleProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        addr += mbi.RegionSize;

        if (mbi.State != MEM_COMMIT)
            continue;

        if (mbi.Protect & PAGE_NOACCESS)
            continue;

        if (mbi.Protect & PAGE_GUARD)
            continue;

        std::vector<uint8_t> buffer(mbi.RegionSize);
        SIZE_T bytesRead;
        buffer.resize(mbi.RegionSize);

        if (!ReadProcessMemory(
            handleProcess,
            mbi.BaseAddress,
            buffer.data(),
            buffer.size(),
            &bytesRead)) {
            // THIS IS NORMAL, just skip
            continue;
        }

        for (size_t i = 0; i + sizeof(int) <= bytesRead; ++i) {
            if (*reinterpret_cast<int *>(buffer.data() + i) == target) {
                uintptr_t found = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i;
                candidates.push_back(found);
            }
        }
    }

    std::cout << "First scan found "
            << candidates.size()
            << " candidates\n";

    while (true) {
        std::cout << "[n] next scan | [d] dump candidates | [q] quit: ";
        std::string cmd;
        std::cin >> cmd;

        if (cmd == "q")
            break;

        if (cmd == "n") {
            int newValue;
            std::cout << "New value: ";
            std::cin >> newValue;

            refineScan(handleProcess, newValue, candidates);

            std::cout << "Remaining candidates: "
                    << candidates.size() << "\n";
        }
        if (cmd == "d") {
            memoryDump(candidates);
            std::cout << std::endl;
        }
    }
}

// 0x208704F4E84
