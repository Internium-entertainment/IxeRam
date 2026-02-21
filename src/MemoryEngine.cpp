#include "MemoryEngine.hpp"
#include <fstream>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <sys/uio.h>
#include <unistd.h>

MemoryEngine::MemoryEngine() : target_pid(-1) {}

MemoryEngine::~MemoryEngine() { detach(); }

bool MemoryEngine::attach(pid_t pid) {
  if (kill(pid, 0) == -1)
    return false;
  target_pid = pid;
  update_maps();
  return true;
}

void MemoryEngine::detach() {
  target_pid = -1;
  regions.clear();
}

bool MemoryEngine::read_memory(uintptr_t address, void *buffer, size_t size) {
  if (target_pid == -1)
    return false;

  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = buffer;
  local[0].iov_len = size;
  remote[0].iov_base = (void *)address;
  remote[0].iov_len = size;

  ssize_t nread = process_vm_readv(target_pid, local, 1, remote, 1, 0);
  return nread == (ssize_t)size;
}

bool MemoryEngine::write_memory(uintptr_t address, const void *buffer,
                                size_t size) {
  if (target_pid == -1)
    return false;

  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = (void *)buffer;
  local[0].iov_len = size;
  remote[0].iov_base = (void *)address;
  remote[0].iov_len = size;

  ssize_t nwritten = process_vm_writev(target_pid, local, 1, remote, 1, 0);
  return nwritten == (ssize_t)size;
}

std::vector<MemoryRegion> MemoryEngine::update_maps() {
  regions.clear();
  if (target_pid == -1)
    return regions;

  std::string path = "/proc/" + std::to_string(target_pid) + "/maps";
  std::ifstream maps_file(path);
  std::string line;

  while (std::getline(maps_file, line)) {
    std::istringstream iss(line);
    std::string address_range, perms, offset, dev, inode, pathname;

    iss >> address_range >> perms >> offset >> dev >> inode;
    std::getline(iss, pathname); // Pathname might be empty or have spaces

    size_t dash_pos = address_range.find('-');
    if (dash_pos != std::string::npos) {
      MemoryRegion region;
      region.start =
          std::stoull(address_range.substr(0, dash_pos), nullptr, 16);
      region.end = std::stoull(address_range.substr(dash_pos + 1), nullptr, 16);
      region.permissions = perms;
      try {
        region.file_offset = std::stoull(offset, nullptr, 16);
      } catch (...) {
        region.file_offset = 0;
      }

      // Trim leading spaces from pathname
      size_t first = pathname.find_first_not_of(' ');
      if (first != std::string::npos) {
        region.pathname = pathname.substr(first);
      } else {
        region.pathname = "";
      }

      regions.push_back(region);
    }
  }
  return regions;
}
