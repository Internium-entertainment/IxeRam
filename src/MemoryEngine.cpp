#include "MemoryEngine.hpp"
#include <fstream>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <sys/uio.h>
#include <unistd.h>

MemoryEngine::MemoryEngine() : target_pid(-1) {}

MemoryEngine::~MemoryEngine() { detach(); }

bool MemoryEngine::attach(pid_t pid) {
  if (kill(pid, 0) == -1)
    return false;

  std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
  if (access(mem_path.c_str(), R_OK | W_OK) != 0) {
    throw std::runtime_error("Permission denied to /proc/" +
                             std::to_string(pid) +
                             "/mem! Enable ptrace_scope or run as root.");
  }

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
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

bool MemoryEngine::read_memory_batch(const std::vector<uintptr_t> &addresses,
                                     void *buffers, size_t item_size) {
  if (target_pid == -1 || addresses.empty())
    return false;

  size_t total = addresses.size();
  size_t processed = 0;

  while (processed < total) {
    size_t chunk_size = std::min(total - processed, (size_t)IOV_MAX);
    std::vector<struct iovec> locals(chunk_size);
    std::vector<struct iovec> remotes(chunk_size);

    for (size_t i = 0; i < chunk_size; ++i) {
      locals[i].iov_base = (uint8_t *)buffers + (processed + i) * item_size;
      locals[i].iov_len = item_size;
      remotes[i].iov_base = (void *)addresses[processed + i];
      remotes[i].iov_len = item_size;
    }

    ssize_t nread = process_vm_readv(target_pid, locals.data(), chunk_size,
                                     remotes.data(), chunk_size, 0);
    if (nread != (ssize_t)(chunk_size * item_size)) {
      // If full batch fails, try one by one for this batch to at least get what
      // we can
      for (size_t i = 0; i < chunk_size; ++i) {
        read_memory(addresses[processed + i],
                    (uint8_t *)buffers + (processed + i) * item_size,
                    item_size);
      }
    }
    processed += chunk_size;
  }
  return true;
}

bool MemoryEngine::write_memory(uintptr_t address, const void *buffer,
                                size_t size) {
  if (target_pid == -1)
    return false;

  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = const_cast<void *>(buffer);
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

bool MemoryEngine::pause_process() {
  if (target_pid <= 0)
    return false;
  if (kill(target_pid, SIGSTOP) == 0) {
    process_paused = true;
    return true;
  }
  return false;
}

bool MemoryEngine::resume_process() {
  if (target_pid <= 0)
    return false;
  if (kill(target_pid, SIGCONT) == 0) {
    process_paused = false;
    return true;
  }
  return false;
}

bool MemoryEngine::kill_process() {
  if (target_pid <= 0)
    return false;
  if (kill(target_pid, SIGKILL) == 0) {
    target_pid = 0;
    process_paused = false;
    return true;
  }
  return false;
}
