#include "MemoryEngine.hpp"
#include "Scanner.hpp"
#include "TUI.hpp"
#include <iostream>
#include <unistd.h>

int main() {
  if (geteuid() != 0) {
    std::cerr << "!!! ERROR: This tool requires root privileges (sudo) to "
                 "access other processes memory !!!"
              << std::endl;
    return 1;
  }
  MemoryEngine engine;
  Scanner scanner(engine);
  TUI tui(engine, scanner);

  tui.run();

  return 0;
}
