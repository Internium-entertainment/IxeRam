# IxeRam

![IxeRam TUI](image.png)

**IxeRam** is an advanced terminal-based (TUI) memory scanner, debugger, and manipulator for Linux. 

Made by **Internium Entertainment**
Thanks to developers: myster_gif

## Features

- **Process Memory Scanning**: Scan for integer, float, strings, and byte arrays in memory.
- **Dynamic Pointer Scanning**: Discover and track static pointer paths that survive process restarts.
- **Interactive Disassembler**: Real-time view of x86-64 assembly instructions.
- **Auto-Assembler Patching**: Use inline assembly to patch instructions on the fly (powered by Keystone Engine).
- **Structure Dissector**: Analyze custom memory structures and visualize offsets as hex, variables, float and strings all at once.
- **Speedhack Configuration**: Alter the target process speed (requires `libspeedhack.so` via `LD_PRELOAD`).
- **Memory Map & Call Graph**: Analyze the internal structure, heap, modules, and call traces in real-time.

## Dependencies

You need to have the following libraries installed:
- C++17 Compiler (g++, clang++)
- CMake
- Capstone Engine (for disassembly)
- Keystone Engine (for assembly patching)
- FTXUI (fetches automatically or via pkg-config)

## Build

Compile using CMake:

```sh
cmake -B build -S .
cmake --build build -j$(nproc)
```

## Usage

Run the compiled executable to start the TUI:

```sh
sudo ./build/memdebug
```
*Note: Depending on your system security configurations (`ptrace_scope`), root privileges might be required to attach to arbitrary process IDs.*

### Speedhack 
To use the speedhack features, launch your target game/process with the compiled shared library:
```sh
LD_PRELOAD=./build/libspeedhack.so ./your_target_executable
```
Then attach **IxeRam** to the process and press `F10` to configure the speed multiplier. 

## Keybindings (TUI)

- **F4**: Attach to PID.
- **F2**: Initial Scan.
- **F7**: Next Scan.
- **F8**: Clear Scan Results.
- **F10**: Speedhack Modal.
- **Space**: Patch Memory (Assembly/Hex) when in Disasm tab.
- **Tab**: Switch Navigation Tabs (Addresses / Map / Call Graph / Watch / Pointers / Disasm / Struct).
- **Q**: Quit.

## License

This project is dual-licensed and managed by Internium-entertainment:

- **Option 1: GNU AGPLv3** (Open Source) – Free for non-commercial networking and local use as long as the project retains the AGPLv3 license.
- **Option 2: InterXlicense v1.0** (Commercial) – Allows modifications and non-commercial usage. Commercial use is permitted ONLY with **explicit written consent** and coordination. The author retains the absolute right to revoke this license at any time.

See the [LICENSE](LICENSE) file for full details.
