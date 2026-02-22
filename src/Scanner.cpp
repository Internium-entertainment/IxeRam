#include "Scanner.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

Scanner::Scanner(MemoryEngine &engine)
    : engine(engine), current_value_type(ValueType::Int32), first_scan(true) {}

// ─── Parse string → raw bytes for specified type
// ───────────────────────────────
std::vector<uint8_t> Scanner::parse_value(const std::string &value_str,
                                          ValueType target_type) const {
  size_t sz = valueTypeSize(target_type);
  std::vector<uint8_t> bytes(sz, 0);

  try {
    switch (target_type) {
    case ValueType::Int8: {
      int8_t v = (int8_t)std::stoi(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::Int16: {
      int16_t v = (int16_t)std::stoi(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::Int32: {
      int32_t v = (int32_t)std::stol(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::Int64: {
      int64_t v = (int64_t)std::stoll(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::UInt8: {
      uint8_t v = (uint8_t)std::stoul(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::UInt16: {
      uint16_t v = (uint16_t)std::stoul(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::UInt32: {
      uint32_t v = (uint32_t)std::stoul(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::UInt64: {
      uint64_t v = (uint64_t)std::stoull(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::Float32: {
      float v = std::stof(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::Float64: {
      double v = std::stod(value_str);
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::Bool: {
      uint8_t v =
          (value_str == "1" || value_str == "true" || value_str == "True") ? 1
                                                                           : 0;
      std::memcpy(bytes.data(), &v, sz);
      break;
    }
    case ValueType::String: {
      bytes.assign(value_str.begin(), value_str.end());
      break;
    }
    case ValueType::String16: {
      for (char c : value_str) {
        bytes.push_back((uint8_t)c);
        bytes.push_back(0);
      }
      break;
    }
    default:
      break;
    }
  } catch (...) {
  }

  return bytes;
}

// ─── Helper: bytes → printable string ────────────────────────────────────────
std::string Scanner::read_value_str(uintptr_t address) const {
  size_t sz = valueTypeSize(current_value_type);
  std::vector<uint8_t> buf(sz, 0);
  if (!engine.read_memory(address, buf.data(), sz))
    return "????";

  try {
    switch (current_value_type) {
    case ValueType::Int8: {
      int8_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string((int)v);
    }
    case ValueType::Int16: {
      int16_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string(v);
    }
    case ValueType::Int32: {
      int32_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string(v);
    }
    case ValueType::Int64: {
      int64_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string(v);
    }
    case ValueType::UInt8: {
      uint8_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string((unsigned)v);
    }
    case ValueType::UInt16: {
      uint16_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string(v);
    }
    case ValueType::UInt32: {
      uint32_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string(v);
    }
    case ValueType::UInt64: {
      uint64_t v;
      std::memcpy(&v, buf.data(), sz);
      return std::to_string(v);
    }
    case ValueType::Float32: {
      float v;
      std::memcpy(&v, buf.data(), sz);
      std::ostringstream ss;
      ss << std::fixed;
      ss.precision(4);
      ss << v;
      return ss.str();
    }
    case ValueType::Float64: {
      double v;
      std::memcpy(&v, buf.data(), sz);
      std::ostringstream ss;
      ss << std::fixed;
      ss.precision(6);
      ss << v;
      return ss.str();
    }
    case ValueType::Bool: {
      uint8_t v;
      std::memcpy(&v, buf.data(), sz);
      return v ? "true" : "false";
    }
    case ValueType::String: {
      // Just showing first 8 chars for brevity in normal lists
      size_t read_sz = 16;
      std::vector<uint8_t> sbuf(read_sz, 0);
      engine.read_memory(address, sbuf.data(), read_sz);
      std::string s;
      for (auto b : sbuf) {
        if (b >= 0x20 && b < 0x7F)
          s += (char)b;
        else if (b == 0)
          break;
      }
      return s;
    }
    case ValueType::String16: {
      size_t read_sz = 32;
      std::vector<uint8_t> sbuf(read_sz, 0);
      engine.read_memory(address, sbuf.data(), read_sz);
      std::string s;
      for (size_t i = 0; i + 1 < read_sz; i += 2) {
        if (sbuf[i + 1] == 0 && sbuf[i] >= 0x20 && sbuf[i] < 0x7F)
          s += (char)sbuf[i];
        else if (sbuf[i] == 0 && sbuf[i + 1] == 0)
          break;
      }
      return s;
    }
    default:
      return "???";
    }
  } catch (...) {
    return "ERR";
  }
}

// ─── Write value to address
// ───────────────────────────────────────────────────
bool Scanner::write_value(uintptr_t address, const std::string &value_str,
                          ValueType type) {
  auto bytes = parse_value(value_str, type);
  if (bytes.empty())
    return false;
  return engine.write_memory(address, bytes.data(), bytes.size());
}

// ─── Initial scan ────────────────────────────────────────────────────────────
template <typename T> void Scanner::initial_scan_typed(T target) {
  scanning_active = true;
  progress = 0;
  results.clear();

  auto regions = engine.update_maps();
  std::vector<MemoryRegion> filtered_regions;
  uint64_t total_size = 0;

  for (const auto &region : regions) {
    if (!region.is_readable() || !region.is_writable())
      continue;
    if (region.pathname == "[vsyscall]")
      continue;
    if ((region.end - region.start) >
        1024 * 1024 * 1024ULL) // 1GB cap per region
      continue;
    filtered_regions.push_back(region);
    total_size += (region.end - region.start);
  }

  if (filtered_regions.empty()) {
    scanning_active = false;
    return;
  }

  std::mutex results_mutex;
  unsigned int num_threads = std::thread::hardware_concurrency();
  if (num_threads == 0)
    num_threads = 4;

  std::vector<std::future<void>> futures;
  std::atomic<uint64_t> bytes_processed{0};

  // Group work into sensible chunks for the thread pool
  for (unsigned int t = 0; t < num_threads; ++t) {
    futures.push_back(std::async(std::launch::async, [&, t, num_threads]() {
      const size_t CHUNK_SIZE = 1024 * 1024;
      std::vector<uint8_t> buffer(CHUNK_SIZE);
      std::vector<ScanResult> local_results;

      for (size_t r_idx = t; r_idx < filtered_regions.size();
           r_idx += num_threads) {
        const auto &region = filtered_regions[r_idx];

        for (uintptr_t addr = region.start; addr < region.end;
             addr += CHUNK_SIZE) {
          size_t to_read = std::min(CHUNK_SIZE, (size_t)(region.end - addr));
          if (to_read < sizeof(T)) {
            bytes_processed += to_read;
            continue;
          }

          if (engine.read_memory(addr, buffer.data(), to_read)) {
            size_t step = aligned_scan ? std::max((size_t)1, sizeof(T)) : 1;
            for (size_t i = 0; i + sizeof(T) <= to_read; i += step) {
              T val;
              std::memcpy(&val, &buffer[i], sizeof(T));

              bool match = false;
              if constexpr (std::is_floating_point_v<T>) {
                match = (std::fabs((double)(val - target)) < 0.001);
              } else {
                match = (val == target);
              }

              if (match) {
                ScanResult sr;
                sr.address = addr + i;
                std::memset(sr.prev_value, 0, 8);
                std::memcpy(sr.prev_value, &val, sizeof(T));
                local_results.push_back(sr);
              }
            }
          }
          bytes_processed += to_read;
          progress = (float)bytes_processed.load() / total_size;
        }
      }

      if (!local_results.empty()) {
        std::lock_guard<std::mutex> lock(results_mutex);
        results.insert(results.end(), local_results.begin(),
                       local_results.end());
      }
    }));
  }

  for (auto &f : futures)
    f.wait();

  // Sort results by address for consistency
  std::sort(results.begin(), results.end(),
            [](const ScanResult &a, const ScanResult &b) {
              return a.address < b.address;
            });

  progress = 1.0f;
  scanning_active = false;
}

void Scanner::initial_scan(ValueType type, const std::string &value_str) {
  current_value_type = type;
  current_value_type = type;
  first_scan = false;
  if (type == ValueType::AOB) {
    aob_scan(value_str);
    return;
  }
  auto target_bytes = parse_value(value_str, current_value_type);

  switch (type) {
  case ValueType::Int8: {
    int8_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::Int16: {
    int16_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::Int32: {
    int32_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::Int64: {
    int64_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::UInt8: {
    uint8_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::UInt16: {
    uint16_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::UInt32: {
    uint32_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::UInt64: {
    uint64_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::Float32: {
    float v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::Float64: {
    double v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::Bool: {
    uint8_t v;
    std::memcpy(&v, target_bytes.data(), sizeof(v));
    initial_scan_typed(v);
    break;
  }
  case ValueType::String:
  case ValueType::String16: {
    std::string hextext;
    for (uint8_t b : target_bytes) {
      char tmp[8];
      snprintf(tmp, sizeof(tmp), "%02X ", b);
      hextext += tmp;
    }
    aob_scan(hextext);
    break;
  }
  default:
    break;
  }
}

// ─── Next scan ───────────────────────────────────────────────────────────────
template <typename T>
void Scanner::next_scan_typed(ScanType scan_type, T target, bool use_target) {
  if (results.empty())
    return;

  scanning_active = true;
  progress = 0;

  std::vector<ScanResult> next_results;
  std::mutex results_mutex;

  unsigned int num_threads = std::thread::hardware_concurrency();
  if (num_threads == 0)
    num_threads = 2;
  if (num_threads > results.size())
    num_threads = results.size();

  size_t chunk_size = results.size() / num_threads;
  std::vector<std::future<void>> futures;
  std::atomic<size_t> items_processed{0};

  for (unsigned int t = 0; t < num_threads; ++t) {
    size_t t_start = t * chunk_size;
    size_t t_end =
        (t == num_threads - 1) ? results.size() : (t + 1) * chunk_size;

    futures.push_back(std::async(std::launch::async, [&, t_start, t_end]() {
      std::vector<ScanResult> local_results;
      const size_t BATCH = 1000;
      std::vector<uintptr_t> addrs(BATCH);
      std::vector<T> values(BATCH);

      for (size_t i = t_start; i < t_end; i += BATCH) {
        size_t current_batch = std::min(BATCH, t_end - i);
        addrs.resize(current_batch);
        values.resize(current_batch);

        for (size_t j = 0; j < current_batch; ++j) {
          addrs[j] = results[i + j].address;
        }

        engine.read_memory_batch(addrs, values.data(), sizeof(T));

        for (size_t j = 0; j < current_batch; ++j) {
          const auto &sr = results[i + j];
          T current_val = values[j];
          T prev_val;
          std::memcpy(&prev_val, sr.prev_value, sizeof(T));

          bool match = false;
          switch (scan_type) {
          case ScanType::ExactValue:
            if constexpr (std::is_floating_point_v<T>)
              match = std::fabs((double)(current_val - target)) < 0.001;
            else
              match = (current_val == target);
            break;
          case ScanType::NotEqual:
            if constexpr (std::is_floating_point_v<T>)
              match = std::fabs((double)(current_val - target)) >= 0.001;
            else
              match = (current_val != target);
            break;
          case ScanType::BiggerThan:
            match = (current_val > target);
            break;
          case ScanType::SmallerThan:
            match = (current_val < target);
            break;
          case ScanType::Between:
            // target holds min; target2 is passed externally (handled in
            // next_scan_between dispatch, so we reuse target as a flag here)
            match = true; // will be filtered outside
            break;
          case ScanType::Increased:
            match = (current_val > prev_val);
            break;
          case ScanType::IncreasedBy:
            if constexpr (std::is_floating_point_v<T>)
              match = std::fabs((double)((current_val - prev_val) - target)) <
                      0.001;
            else
              match = ((current_val - prev_val) == target);
            break;
          case ScanType::Decreased:
            match = (current_val < prev_val);
            break;
          case ScanType::DecreasedBy:
            if constexpr (std::is_floating_point_v<T>)
              match = std::fabs((double)((prev_val - current_val) - target)) <
                      0.001;
            else
              match = ((prev_val - current_val) == target);
            break;
          case ScanType::Changed:
            if constexpr (std::is_floating_point_v<T>)
              match = std::fabs((double)(current_val - prev_val)) >= 0.0001;
            else
              match = (current_val != prev_val);
            break;
          case ScanType::Unchanged:
            if constexpr (std::is_floating_point_v<T>)
              match = std::fabs((double)(current_val - prev_val)) < 0.0001;
            else
              match = (current_val == prev_val);
            break;
          }

          if (match) {
            ScanResult updated;
            updated.address = sr.address;
            std::memset(updated.prev_value, 0, 8);
            std::memcpy(updated.prev_value, &current_val, sizeof(T));
            local_results.push_back(updated);
          }
          items_processed++;
        }
        progress = (float)items_processed.load() / results.size();
      }

      if (!local_results.empty()) {
        std::lock_guard<std::mutex> lock(results_mutex);
        next_results.insert(next_results.end(),
                            std::make_move_iterator(local_results.begin()),
                            std::make_move_iterator(local_results.end()));
      }
    }));
  }

  for (auto &f : futures)
    f.wait();

  results = std::move(next_results);
  progress = 1.0f;
  scanning_active = false;
}

void Scanner::next_scan(ScanType scan_type, const std::string &value_str) {
  // Special case: Between needs two values "min,max"
  if (scan_type == ScanType::Between) {
    // Parse "min,max" or "min max"
    std::string s = value_str;
    for (auto &c : s)
      if (c == ',')
        c = ' ';
    std::istringstream iss2(s);
    std::string smin, smax;
    iss2 >> smin >> smax;
    if (smin.empty() || smax.empty())
      return;
    // Run as BiggerThan(min) then filter with SmallerThan(max)
    // Use a direct approach: scan with Changed (captures all), then filter
    // We run BiggerThan(min) pass, store, then do SmallerThan(max) on that
    next_scan(ScanType::BiggerThan, smin);
    next_scan(ScanType::SmallerThan, smax);
    return;
  }

  auto target_bytes = parse_value(value_str, current_value_type);
  bool use_target = !value_str.empty();

  switch (current_value_type) {
  case ValueType::Int8: {
    int8_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::Int16: {
    int16_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::Int32: {
    int32_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::Int64: {
    int64_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::UInt8: {
    uint8_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::UInt16: {
    uint16_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::UInt32: {
    uint32_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::UInt64: {
    uint64_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::Float32: {
    float v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::Float64: {
    double v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  case ValueType::Bool: {
    uint8_t v = 0;
    if (use_target)
      std::memcpy(&v, target_bytes.data(), sizeof(v));
    next_scan_typed(scan_type, v, use_target);
    break;
  }
  default:
    break;
  }
}

// ─── AOB Scan ────────────────────────────────────────────────────────────────
void Scanner::aob_scan(const std::string &pattern) {
  scanning_active = true;
  progress = 0;
  results.clear();

  std::vector<int> pattern_bytes;
  std::istringstream iss(pattern);
  std::string tok;
  while (iss >> tok) {
    if (tok == "?" || tok == "??")
      pattern_bytes.push_back(-1);
    else
      pattern_bytes.push_back(std::stoi(tok, nullptr, 16));
  }
  if (pattern_bytes.empty()) {
    scanning_active = false;
    return;
  }

  auto regions = engine.update_maps();
  std::vector<MemoryRegion> filtered_regions;
  uint64_t total_size = 0;

  for (const auto &region : regions) {
    if (!region.is_readable() || region.pathname == "[vsyscall]")
      continue;
    if ((region.end - region.start) > 1024 * 1024 * 1024ULL)
      continue;
    filtered_regions.push_back(region);
    total_size += (region.end - region.start);
  }

  if (filtered_regions.empty()) {
    scanning_active = false;
    return;
  }

  std::mutex results_mutex;
  unsigned int num_threads = std::thread::hardware_concurrency();
  if (num_threads == 0)
    num_threads = 4;

  std::vector<std::future<void>> futures;
  std::atomic<uint64_t> bytes_processed{0};

  for (unsigned int t = 0; t < num_threads; ++t) {
    futures.push_back(std::async(std::launch::async, [&, t, num_threads,
                                                      pattern_bytes]() {
      const size_t CHUNK_SIZE = 1024 * 1024;
      std::vector<uint8_t> buffer(CHUNK_SIZE);
      std::vector<ScanResult> local_results;

      for (size_t r_idx = t; r_idx < filtered_regions.size();
           r_idx += num_threads) {
        const auto &region = filtered_regions[r_idx];

        for (uintptr_t addr = region.start; addr < region.end;
             addr += CHUNK_SIZE) {
          size_t to_read = std::min(CHUNK_SIZE, (size_t)(region.end - addr));
          if (to_read < pattern_bytes.size()) {
            bytes_processed += to_read;
            continue;
          }

          if (engine.read_memory(addr, buffer.data(), to_read)) {
            uint8_t first_byte =
                (pattern_bytes[0] == -1) ? 0 : (uint8_t)pattern_bytes[0];
            bool first_wild = (pattern_bytes[0] == -1);

            for (size_t i = 0; i + pattern_bytes.size() <= to_read; ++i) {
              if (!first_wild) {
                uint8_t *p = (uint8_t *)std::memchr(
                    &buffer[i], first_byte,
                    to_read - i - pattern_bytes.size() + 1);
                if (!p)
                  break;
                i = p - &buffer[0];
              }

              bool match = true;
              // If first_wild is false, the first byte is already matched by
              // memchr. If first_wild is true, pattern_bytes[0] is -1, so it
              // always matches. In both cases, we start checking from the
              // second byte (index 1).
              for (size_t j = 1; j < pattern_bytes.size();
                   ++j) { // Start from 1
                if (pattern_bytes[j] != -1 &&
                    buffer[i + j] != (uint8_t)pattern_bytes[j]) {
                  match = false;
                  break;
                }
              }

              if (match) {
                ScanResult sr;
                sr.address = addr + i;
                std::memset(sr.prev_value, 0, 8);
                size_t copy_sz = std::min((size_t)8, pattern_bytes.size());
                std::memcpy(sr.prev_value, &buffer[i], copy_sz);
                local_results.push_back(sr);
              }
            }
          }
          bytes_processed += to_read;
          progress = (float)bytes_processed.load() / total_size;
        }
      }

      if (!local_results.empty()) {
        std::lock_guard<std::mutex> lock(results_mutex);
        results.insert(results.end(), local_results.begin(),
                       local_results.end());
      }
    }));
  }

  for (auto &f : futures)
    f.wait();

  std::sort(results.begin(), results.end(),
            [](const ScanResult &a, const ScanResult &b) {
              return a.address < b.address;
            });

  progress = 1.0f;
  scanning_active = false;
}

bool Scanner::match_pattern(const std::vector<uint8_t> &data,
                            const std::vector<int> &pattern) {
  if (data.size() < pattern.size())
    return false;
  for (size_t j = 0; j < pattern.size(); ++j)
    if (pattern[j] != -1 && data[j] != (uint8_t)pattern[j])
      return false;
  return true;
}

std::vector<Scanner::PointerPath>
Scanner::find_pointers(uintptr_t target_addr, int max_depth, int max_offset) {
  std::vector<PointerPath> found;
  auto regions = engine.update_maps();

  // Step 1: Scan for first level (who points to target_addr or close to it)
  // For simplicity, we search for exact or near pointers in one pass
  const size_t CHUNK = 1024 * 1024;
  std::vector<uint8_t> buffer(CHUNK);

  struct Candidate {
    uintptr_t addr;
    int64_t offset;
  };
  std::vector<Candidate> current_level;
  current_level.push_back({target_addr, 0});

  for (int depth = 0; depth < max_depth; ++depth) {
    std::vector<Candidate> next_level;
    for (const auto &region : regions) {
      if (!region.is_readable())
        continue;

      for (uintptr_t addr = region.start; addr < region.end; addr += CHUNK) {
        size_t to_read = std::min(CHUNK, (size_t)(region.end - addr));
        if (to_read < sizeof(uintptr_t))
          continue;
        if (!engine.read_memory(addr, buffer.data(), to_read))
          continue;

        for (size_t i = 0; i + sizeof(uintptr_t) <= to_read; ++i) {
          uintptr_t val;
          std::memcpy(&val, &buffer[i], sizeof(uintptr_t));

          for (const auto &cand : current_level) {
            int64_t diff = (int64_t)cand.addr - (int64_t)val;
            if (std::abs(diff) < max_offset) {
              uintptr_t ptr_loc = addr + i;

              // If this location is in a module, we found a base!
              bool in_module = false;
              for (const auto &mod : regions) {
                if (mod.pathname != "" && mod.pathname[0] == '/' &&
                    ptr_loc >= mod.start && ptr_loc < mod.end) {
                  PointerPath path;
                  path.base_module_addr = mod.start;
                  path.module_name =
                      mod.pathname.substr(mod.pathname.find_last_of('/') + 1);
                  path.offsets.push_back(diff);
                  path.final_address = target_addr;
                  found.push_back(std::move(path));
                  in_module = true;
                  break;
                }
              }

              if (!in_module && depth < max_depth - 1) {
                next_level.push_back({ptr_loc, diff});
              }
            }
          }
        }
      }
    }
    if (found.size() > 100)
      break; // Limit results

    if (next_level.size() > 2000)
      next_level.resize(
          2000); // Prevent exponential explosion but still scan deeply
    current_level = std::move(next_level);
  }

  return found;
}

// Store a copy in the cache for save/load
// (We update find_pointers_cache at the call site in TUI, not here,
//  since find_pointers is const-ish and takes target_addr)
// Actually update cache here:
void Scanner_update_ptr_cache(Scanner *s,
                              std::vector<Scanner::PointerPath> &v) {
  s->find_pointers_cache = v;
}

// ─── Unknown Initial Value Scan
// ──────────────────────────────────────────────────────
void Scanner::unknown_initial_scan(ValueType type) {
  current_value_type = type;
  first_scan = false;
  scanning_active = true;
  progress = 0;
  results.clear();

  size_t item_size = valueTypeSize(type);
  if (item_size == 0)
    item_size = 4;

  auto regions = engine.update_maps();
  std::vector<MemoryRegion> filtered;
  uint64_t total_size = 0;

  for (const auto &r : regions) {
    if (!r.is_readable() || !r.is_writable())
      continue;
    if (r.pathname == "[vsyscall]")
      continue;
    if ((r.end - r.start) > 1024 * 1024 * 1024ULL)
      continue;
    filtered.push_back(r);
    total_size += (r.end - r.start);
  }

  std::mutex mtx;
  unsigned num_threads = std::thread::hardware_concurrency();
  if (num_threads == 0)
    num_threads = 4;
  std::vector<std::future<void>> futures;
  std::atomic<uint64_t> bytes_processed{0};

  for (unsigned t = 0; t < num_threads; ++t) {
    futures.push_back(std::async(std::launch::async, [&, t, num_threads]() {
      const size_t CHUNK = 1024 * 1024;
      std::vector<uint8_t> buf(CHUNK);
      std::vector<ScanResult> local;

      for (size_t r_idx = t; r_idx < filtered.size(); r_idx += num_threads) {
        const auto &reg = filtered[r_idx];
        for (uintptr_t addr = reg.start; addr < reg.end; addr += CHUNK) {
          size_t to_read = std::min(CHUNK, (size_t)(reg.end - addr));
          if (to_read < item_size) {
            bytes_processed += to_read;
            continue;
          }
          if (engine.read_memory(addr, buf.data(), to_read)) {
            size_t step = aligned_scan ? std::max((size_t)1, item_size) : 1;
            for (size_t i = 0; i + item_size <= to_read; i += step) {
              ScanResult sr;
              sr.address = addr + i;
              std::memset(sr.prev_value, 0, 8);
              std::memcpy(sr.prev_value, &buf[i],
                          std::min(item_size, (size_t)8));
              local.push_back(sr);
            }
          }
          bytes_processed += to_read;
          progress = (float)bytes_processed.load() / total_size;
        }
      }
      if (!local.empty()) {
        std::lock_guard<std::mutex> lk(mtx);
        results.insert(results.end(), local.begin(), local.end());
      }
    }));
  }
  for (auto &f : futures)
    f.wait();

  std::sort(results.begin(), results.end(),
            [](const ScanResult &a, const ScanResult &b) {
              return a.address < b.address;
            });
  progress = 1.0f;
  scanning_active = false;
}

// ─── Save / Load Pointer Results
// ────────────────────────────────────────────────────
bool Scanner::save_ptr_results(const std::string &path) const {
  std::ofstream f(path);
  if (!f)
    return false;
  f << "# IxeRam Pointer Map\n";
  for (const auto &p : find_pointers_cache) {
    f << p.module_name << "," << std::hex << p.base_module_addr;
    for (auto o : p.offsets)
      f << "," << std::dec << o;
    f << "\n";
  }
  return true;
}

bool Scanner::load_ptr_results(const std::string &path) {
  std::ifstream f(path);
  if (!f)
    return false;
  find_pointers_cache.clear();
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    std::istringstream iss(line);
    std::string tok;
    PointerPath pp;
    bool first = true;
    bool second = true;
    while (std::getline(iss, tok, ',')) {
      if (first) {
        pp.module_name = tok;
        first = false;
      } else if (second) {
        try {
          pp.base_module_addr = std::stoull(tok, nullptr, 16);
        } catch (...) {
        }
        second = false;
      } else {
        try {
          pp.offsets.push_back(std::stoll(tok));
        } catch (...) {
        }
      }
    }
    if (!pp.module_name.empty())
      find_pointers_cache.push_back(pp);
  }
  return true;
}
