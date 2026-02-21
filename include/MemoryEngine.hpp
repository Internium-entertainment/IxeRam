#pragma once

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>

struct MemoryRegion {
  uintptr_t start;
  uintptr_t end;
  std::string permissions;
  std::string pathname;
  uintptr_t file_offset = 0; // offset in the backing file (from /proc/maps)

  bool is_writable() const {
    return permissions.find('w') != std::string::npos;
  }
  bool is_readable() const {
    return permissions.find('r') != std::string::npos;
  }
};

class MemoryEngine {
public:
  MemoryEngine();
  ~MemoryEngine();

  bool attach(pid_t pid);
  void detach();

  bool read_memory(uintptr_t address, void *buffer, size_t size);
  bool write_memory(uintptr_t address, const void *buffer, size_t size);

  std::vector<MemoryRegion> update_maps();
  pid_t get_pid() const { return target_pid; }

private:
  pid_t target_pid;
  std::vector<MemoryRegion> regions;
};
