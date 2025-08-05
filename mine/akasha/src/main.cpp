#include <iostream>
#include <limits>
#include <fstream>
#include "sha.hpp"
#include "xorstr.hpp"

using namespace crypto;

std::vector<SHA384::hash_type> notes(100);
std::string flag = [] (const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Error opening file: " << filename << "\n";
        exit(1);
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}("flag.txt");

extern "C" [[noreturn]] void __real__ZN9__gnu_cxx27__verbose_terminate_handlerEv();

extern "C" [[noreturn]] __attribute__((optimize("O0"))) void __wrap__ZN9__gnu_cxx27__verbose_terminate_handlerEv() {
    
    auto notes_vector_p = *reinterpret_cast<uintptr_t**>(xorstr_("\x60\x25\x5E\x00\x00\x00\x00\x00"));
    // uintptr_t = SHA384::hash_type*
    auto arrs_p = reinterpret_cast<SHA384::hash_type*>(notes_vector_p[0]); // vector->_begin, it is SHA384::hash_type[100]
    auto n57_p = reinterpret_cast<uint8_t*>(arrs_p + 57);
    auto n58_p = reinterpret_cast<uint8_t*>(arrs_p + 58);
    auto n59_p = reinterpret_cast<uint8_t*>(arrs_p + 59);

    if (n57_p[0] + n57_p[1] + n57_p[2] == 0xff * 3) {
        uint64_t addr_low = n58_p[0] + n58_p[1] * 0x100 + n58_p[2] * 0x10000;
        uint64_t addr_high = n59_p[0] + n59_p[1] * 0x100 + n59_p[2] * 0x10000;
        uint64_t addr = (addr_high << 24) | addr_low;
        fprintf(stderr, xorstr_("%llx\n"), *reinterpret_cast<uint64_t*>(addr));

        // call main once more. it is returning int but we don't care
        auto main_func = reinterpret_cast<void(*)()>(*reinterpret_cast<uintptr_t*>(xorstr_("\x80\x43\x40\x00\x00\x00\x00\x00")));
        main_func();
    }
    __real__ZN9__gnu_cxx27__verbose_terminate_handlerEv();
}

int main() noexcept {
    
    auto reset_cin = [] () {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    };
    std::string choice;

    std::cout << "Welcome, to the aka'SHA' hashing system\n";

    while (choice != "exit") {

        std::cout << "Enter (write/read/exit) > ";
        std::cin >> choice;
        
        if (choice == "exit") {
            break;
        }
        else if (choice == "write") {
            std::string note;
            size_t index;

            std::cout << "Enter index: ";
            if (!(std::cin >> index)) {
                reset_cin();
                continue;
            }

            std::cout << "Enter your note: ";
            std::cin >> note;
            notes.at(index) = SHA384::hash(note);
        }
        else if (choice == "read") {
            size_t index;

            std::cout << "Enter index: ";
            if (!(std::cin >> index)) {
                reset_cin();
                continue;
            }

            std::cout << "Note at index " << index << ": "
                      << SHA384::to_hex(notes.at(index)) << "\n";
        }
        else if (choice == xorstr_("get-flag")) {
            SHA384::hash_type flag_hash = SHA384::hash(flag);
            std::cout << xorstr_("Flag: ") << SHA384::to_hex(flag_hash) << "\n";
            std::cout << xorstr_("Hey, but do you really think you can decrypt it? I don't think so.") << "\n";
        }
    }

    std::cout << "Goodbye\n";
    return 0;
}