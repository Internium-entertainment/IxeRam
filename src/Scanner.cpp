#include "Scanner.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

Scanner::Scanner(MemoryEngine &engine)
    : engine(engine), current_value_type(ValueType::Int32), first_scan(true) {}

// ─── Parse string → raw bytes for current type ───────────────────────────────
std::vector<uint8_t> Scanner::parse_value(const std::string &value_str) const {
  size_t sz = valueTypeSize(current_value_type);
  std::vector<uint8_t> bytes(sz, 0);

  try {
    switch (current_value_type) {
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
bool Scanner::write_value(uintptr_t address, const std::string &value_str) {
  auto bytes = parse_value(value_str);
  if (bytes.empty())
    return false;
  return engine.write_memory(address, bytes.data(), bytes.size());
}

// ─── Initial scan ────────────────────────────────────────────────────────────
template <typename T> void Scanner::initial_scan_typed(T target) {
  results.clear();
  auto regions = engine.update_maps();
  const size_t CHUNK = 65536;
  std::vector<uint8_t> buffer(CHUNK);

  for (const auto &region : regions) {
    if (!region.is_readable() || !region.is_writable())
      continue;
    if (region.pathname == "[vsyscall]")
      continue;
    // Skip very large regions to be somewhat fast
    if ((region.end - region.start) > 512 * 1024 * 1024ULL)
      continue;

    for (uintptr_t addr = region.start; addr < region.end; addr += CHUNK) {
      size_t to_read = std::min(CHUNK, (size_t)(region.end - addr));
      if (to_read < sizeof(T))
        continue;
      if (!engine.read_memory(addr, buffer.data(), to_read))
        continue;

      for (size_t i = 0; i + sizeof(T) <= to_read; ++i) {
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
          sr.prev_value.resize(sizeof(T));
          std::memcpy(sr.prev_value.data(), &val, sizeof(T));
          results.push_back(std::move(sr));
        }
      }
    }
  }
}

void Scanner::initial_scan(ValueType type, const std::string &value_str) {
  current_value_type = type;
  first_scan = false;
  if (type == ValueType::AOB) {
    aob_scan(value_str);
    return;
  }
  auto target_bytes = parse_value(value_str);

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
  std::vector<ScanResult> next_results;
  next_results.reserve(results.size());

  for (auto &sr : results) {
    T current_val;
    if (!engine.read_memory(sr.address, &current_val, sizeof(T)))
      continue;

    T prev_val;
    if (sr.prev_value.size() == sizeof(T))
      std::memcpy(&prev_val, sr.prev_value.data(), sizeof(T));
    else
      prev_val = current_val; // fallback

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
    case ScanType::Increased:
      match = (current_val > prev_val);
      break;
    case ScanType::IncreasedBy:
      if constexpr (std::is_floating_point_v<T>)
        match = std::fabs((double)((current_val - prev_val) - target)) < 0.001;
      else
        match = ((current_val - prev_val) == target);
      break;
    case ScanType::Decreased:
      match = (current_val < prev_val);
      break;
    case ScanType::DecreasedBy:
      if constexpr (std::is_floating_point_v<T>)
        match = std::fabs((double)((prev_val - current_val) - target)) < 0.001;
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
      updated.prev_value.resize(sizeof(T));
      std::memcpy(updated.prev_value.data(), &current_val, sizeof(T));
      next_results.push_back(std::move(updated));
    }
  }
  results = std::move(next_results);
}

void Scanner::next_scan(ScanType scan_type, const std::string &value_str) {
  auto target_bytes = parse_value(value_str);
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
  if (pattern_bytes.empty())
    return;

  auto regions = engine.update_maps();
  const size_t CHUNK = 65536;
  std::vector<uint8_t> buffer(CHUNK);

  for (const auto &region : regions) {
    if (!region.is_readable() || region.pathname == "[vsyscall]")
      continue;
    if ((region.end - region.start) > 512 * 1024 * 1024ULL)
      continue;

    for (uintptr_t addr = region.start; addr < region.end; addr += CHUNK) {
      size_t to_read = std::min(CHUNK, (size_t)(region.end - addr));
      if (to_read < pattern_bytes.size())
        continue;
      if (!engine.read_memory(addr, buffer.data(), to_read))
        continue;

      for (size_t i = 0; i + pattern_bytes.size() <= to_read; ++i) {
        bool m = true;
        for (size_t j = 0; j < pattern_bytes.size(); ++j) {
          if (pattern_bytes[j] != -1 &&
              buffer[i + j] != (uint8_t)pattern_bytes[j]) {
            m = false;
            break;
          }
        }
        if (m) {
          ScanResult sr;
          sr.address = addr + i;
          sr.prev_value.assign(buffer.begin() + i,
                               buffer.begin() + i + pattern_bytes.size());
          results.push_back(std::move(sr));
        }
      }
    }
  }
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
    // current_level = next_level; // For full recursion, but too slow for now
  }

  return found;
}
