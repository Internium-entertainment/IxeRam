// ════════════════════════════════════════════════════════════════════════
//  MEMORY INSPECTOR — TUI.cpp  (Part 1: helpers)
// ════════════════════════════════════════════════════════════════════════
#include "TUI.hpp"
#include "KittyGraphics.hpp"
#include "ftxui/component/component_options.hpp"
#include "ftxui/component/event.hpp"
#include "ftxui/dom/canvas.hpp"
#include "ftxui/dom/elements.hpp"
#include "ftxui/screen/color.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
using namespace ftxui;

// ODR for constexpr arrays
constexpr const char *TUI::VALUE_TYPE_NAMES[];
constexpr ValueType TUI::VALUE_TYPES[];
constexpr const char *TUI::SCAN_TYPE_NAMES[];
constexpr ScanType TUI::SCAN_TYPES[];

// ─── ctor / dtor ─────────────────────────────────────────────────────────
TUI::TUI(MemoryEngine &e, Scanner &s) : engine(e), scanner(s) {
  add_log("Memory Inspector ready. Attach a PID to begin.");
}
TUI::~TUI() {}

// ─── Logging ─────────────────────────────────────────────────────────────
void TUI::add_log(const std::string &msg) {
  logs.push_back("◈ " + msg);
  if (logs.size() > 80)
    logs.erase(logs.begin());
}

// ─── read_as_double ──────────────────────────────────────────────────────
double TUI::read_as_double(uintptr_t addr) const {
  if (!addr)
    return 0.0;
  size_t sz = valueTypeSize(scanner.get_value_type());
  std::vector<uint8_t> b(sz, 0);
  if (!engine.read_memory(addr, b.data(), sz))
    return 0.0;
  switch (scanner.get_value_type()) {
  case ValueType::Int8: {
    int8_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::Int16: {
    int16_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::Int32: {
    int32_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::Int64: {
    int64_t v;
    memcpy(&v, b.data(), sz);
    return (double)v;
  }
  case ValueType::UInt8: {
    uint8_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::UInt16: {
    uint16_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::UInt32: {
    uint32_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::UInt64: {
    uint64_t v;
    memcpy(&v, b.data(), sz);
    return (double)v;
  }
  case ValueType::Float32: {
    float v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::Float64: {
    double v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  case ValueType::Bool: {
    uint8_t v;
    memcpy(&v, b.data(), sz);
    return v;
  }
  default:
    return 0.0;
  }
}

std::string TUI::addr_type_str(AddressType t) const {
  switch (t) {
  case AddressType::Code:
    return "C";
  case AddressType::Data:
    return "D";
  case AddressType::Heap:
    return "H";
  case AddressType::Stack:
    return "S";
  default:
    return "?";
  }
}

// ─── update_tracking_data ────────────────────────────────────────────────
void TUI::update_tracking_data() {
  auto &raw = scanner.get_results();
  if (raw.empty()) {
    categorized_results.clear();
    return;
  }

  auto regions = engine.update_maps();
  // Sort regions by start address to allow binary search
  std::sort(regions.begin(), regions.end(),
            [](const auto &a, const auto &b) { return a.start < b.start; });

  // Only re-categorize ALL if the result count changed or it's the first time
  static size_t last_raw_size = 0;
  bool full_update = (raw.size() != last_raw_size);
  last_raw_size = raw.size();

  if (full_update) {
    categorized_results.clear();
    categorized_results.reserve(raw.size());

    for (const auto &sr : raw) {
      AddressType atype = AddressType::Other;
      int score = 10;
      std::string mod_name = "[anon]";
      uintptr_t base = 0;
      uintptr_t f_off = 0;

      // Binary search for the region
      auto it = std::upper_bound(
          regions.begin(), regions.end(), sr.address,
          [](uintptr_t addr, const auto &reg) { return addr < reg.start; });

      if (it != regions.begin()) {
        const auto &reg = *(--it);
        if (sr.address >= reg.start && sr.address < reg.end) {
          base = reg.start;
          f_off = reg.file_offset;
          size_t sl = reg.pathname.find_last_of('/');
          mod_name = (sl != std::string::npos) ? reg.pathname.substr(sl + 1)
                                               : reg.pathname;
          if (mod_name.empty())
            mod_name = "[anon]";

          if (reg.permissions.find('x') != std::string::npos) {
            atype = AddressType::Code;
            score += 60;
          } else if (reg.pathname.find("[heap]") != std::string::npos) {
            atype = AddressType::Heap;
            score += 30;
          } else if (reg.pathname.find("[stack]") != std::string::npos) {
            atype = AddressType::Stack;
            score += 5;
          } else if (!reg.pathname.empty()) {
            atype = AddressType::Data;
            score += 40;
          }
        }
      }
      categorized_results.push_back(
          {sr.address, atype, score, mod_name, base, f_off});
    }

    // Sort by type only when results change
    std::sort(
        categorized_results.begin(), categorized_results.end(),
        [](const auto &a, const auto &b) { return (int)a.type < (int)b.type; });
  }

  if (selected_result_idx >= (int)categorized_results.size())
    selected_result_idx = 0;

  if (!categorized_results.empty()) {
    tracked_address = categorized_results[selected_result_idx].addr;
    double cur = read_as_double(tracked_address);
    value_history.push_back((float)cur);
    if (value_history.size() > 120)
      value_history.erase(value_history.begin());

    hex_dump.resize(512, 0);
    engine.read_memory(tracked_address, hex_dump.data(), 512);
    if (show_disasm || main_tab == 5)
      update_disasm();
  }

  // Update Watchlist cached values (always do this for real-time)
  for (auto &we : watchlist) {
    we.cached_val = scanner.read_value_str(we.addr);
  }
}

// ─── update_memory_map ──────────────────────────────────────────────────
void TUI::update_memory_map() {
  map_entries.clear();
  auto regions = engine.update_maps();
  for (const auto &reg : regions) {
    MapEntry e;
    e.start = reg.start;
    e.end = reg.end;
    e.module_full = reg.pathname;

    // Wine/Proton support: paths can be Z:\home\... or have .exe/.dll
    std::string path = reg.pathname;
    size_t sl = path.find_last_of('/');
    e.module = (sl != std::string::npos) ? path.substr(sl + 1) : path;

    // If it's a wine preloader or similar, try to keep the original name
    if (e.module.empty())
      e.module = "[anonymous]";
    else if (e.module == "wine64-preloader" || e.module == "wine-preloader") {
      // Keep it, but maybe mark it
    }

    e.size_bytes = reg.end - reg.start;
    e.file_offset = reg.file_offset;
    e.is_stack = path.find("[stack]") != std::string::npos;
    e.is_heap = path.find("[heap]") != std::string::npos;
    e.is_code = reg.permissions.find('x') != std::string::npos;
    map_entries.push_back(e);
  }
}

// ─── update_disasm ──────────────────────────────────────────────────────
void TUI::update_disasm() {
  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return;
  cs_insn *insn;
  size_t count = cs_disasm(handle, hex_dump.data(), hex_dump.size(),
                           tracked_address, 0, &insn);
  disasm_lines.clear();
  if (count > 0) {
    for (size_t i = 0; i < count && i < 35; ++i) {
      std::string bytes_str;
      for (int j = 0; j < insn[i].size; j++) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X ", insn[i].bytes[j]);
        bytes_str += buf;
      }
      disasm_lines.push_back({insn[i].address, insn[i].mnemonic, insn[i].op_str,
                              bytes_str, insn[i].size});
    }
    cs_free(insn, count);
  } else {
    disasm_lines.push_back({0, "ERR", "Cannot disassemble this region", "", 0});
  }
  cs_close(&handle);
}

// ─── freeze loop ─────────────────────────────────────────────────────────
void TUI::freezing_loop() {
  while (true) {
    auto copy = frozen_addresses;
    for (auto &[addr, fe] : copy)
      engine.write_memory(addr, fe.bytes.data(), fe.bytes.size());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

// ─── Heuristic naming ────────────────────────────────────────────────────
// Known x86-64 prologue patterns → predefined label
std::string TUI::match_known_prologue(const std::vector<uint8_t> &b) {
  if (b.size() < 4)
    return "";
  // push rbp; mov rbp, rsp  → 55 48 89 E5
  if (b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xE5)
    return "func_standard";
  // endbr64 → F3 0F 1E FA  (CET-enabled)
  if (b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E && b[3] == 0xFA)
    return "func_cet";
  // sub rsp, N → 48 83 EC
  if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC)
    return "func_leaf";
  // xor eax,eax; ret → 31 C0 C3
  if (b[0] == 0x31 && b[1] == 0xC0 && b[2] == 0xC3)
    return "stub_return_zero";
  // nop sled
  if (b[0] == 0x90 && b[1] == 0x90)
    return "nop_sled";
  return "";
}

std::string TUI::guess_name(uintptr_t addr, const std::vector<uint8_t> &bytes,
                            const MapEntry *region) {
  std::string base_label = "sub";

  // 1. Prologue pattern
  std::string proto = match_known_prologue(bytes);
  if (!proto.empty())
    base_label = proto;

  // 2. Module context heuristics
  std::string mod = region ? region->module : "";
  if (mod.find("libc") != std::string::npos)
    base_label = "libc_" + base_label;
  else if (mod.find("libm") != std::string::npos)
    base_label = "libm_" + base_label;
  else if (mod.find("libpthread") != std::string::npos ||
           mod.find("libthread") != std::string::npos)
    base_label = "thread_" + base_label;
  else if (mod.find("libGL") != std::string::npos ||
           mod.find("libEGL") != std::string::npos)
    base_label = "gfx_" + base_label;
  else if (mod.find("libSDL") != std::string::npos)
    base_label = "sdl_" + base_label;
  else if (mod.find("libssl") != std::string::npos ||
           mod.find("libcrypto") != std::string::npos)
    base_label = "crypto_" + base_label;

  // 3. Scan for nearby ASCII strings (in first 128 bytes)
  std::string found_str;
  for (size_t i = 0; i + 4 < bytes.size(); ++i) {
    if (bytes[i] >= 0x20 && bytes[i] < 0x7F) {
      size_t len = 0;
      while (i + len < bytes.size() && bytes[i + len] >= 0x20 &&
             bytes[i + len] < 0x7F)
        ++len;
      if (len >= 4 && len <= 20) {
        found_str = std::string(bytes.begin() + i, bytes.begin() + i + len);
        // Sanitize: keep only alnum and _
        std::string clean;
        for (char c : found_str)
          if (isalnum(c) || c == '_')
            clean += c;
        if (clean.size() >= 3) {
          base_label = "ref_" + clean;
          break;
        }
      }
      i += len;
    }
  }

  // 4. Append hex offset
  std::ostringstream ss;
  ss << std::hex << std::uppercase << addr;
  return base_label + "_" + ss.str();
}

// ─── build_call_graph ───────────────────────────────────────────────────
void TUI::build_call_graph(uintptr_t root, int max_depth) {
  call_graph.clear();
  cg_index.clear();
  if (!root)
    return;

  auto regions = engine.update_maps();

  // Find region for an address
  auto find_region = [&](uintptr_t addr) -> const MapEntry * {
    for (const auto &e : map_entries)
      if (addr >= e.start && addr < e.end)
        return &e;
    return nullptr;
  };

  // BFS queue: (addr, depth, parent_addr)
  struct QItem {
    uint64_t addr;
    int depth;
  };
  std::vector<QItem> queue;
  std::set<uint64_t> visited;

  queue.push_back({root, 0});
  visited.insert(root);

  while (!queue.empty()) {
    auto [cur_addr, depth] = queue.front();
    queue.erase(queue.begin());

    // Read 256 bytes, disassemble
    std::vector<uint8_t> buf(256, 0);
    engine.read_memory(cur_addr, buf.data(), 256);

    const MapEntry *reg = find_region(cur_addr);

    CallNode node;
    node.addr = cur_addr;
    node.depth = depth;
    node.base_addr = reg ? reg->start : 0;
    node.offset = reg ? (cur_addr - reg->start) : cur_addr;
    node.module = reg ? reg->module : "???";
    node.is_external = (depth > 0 && reg && root > 0 && find_region(root) &&
                        find_region(root) != reg);
    node.name = guess_name(cur_addr, buf, reg);

    // Disassemble to find callees
    if (depth < max_depth) {
      csh handle;
      if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
        cs_insn *insn;
        size_t count =
            cs_disasm(handle, buf.data(), buf.size(), cur_addr, 0, &insn);
        for (size_t i = 0; i < count; ++i) {
          std::string mn = insn[i].mnemonic;
          // Follow direct calls and conditional jumps
          if ((mn == "call" || mn == "jmp") && insn[i].op_str[0] == '0') {
            uint64_t target = 0;
            try {
              target = std::stoull(insn[i].op_str, nullptr, 16);
            } catch (...) {
            }
            if (target && !visited.count(target)) {
              visited.insert(target);
              node.callees.push_back(target);
              queue.push_back({target, depth + 1});
            }
          }
        }
        if (count > 0)
          cs_free(insn, count);
        cs_close(&handle);
      }
    }

    cg_index[cur_addr] = call_graph.size();
    call_graph.push_back(std::move(node));
  }
}

// ─── Ghidra export ───────────────────────────────────────────────────────
void TUI::export_ghidra_script(const std::string &path) {
  std::ofstream f(path);
  if (!f.is_open()) {
    add_log("✗ Cannot write " + path);
    return;
  }

  f << "# Ghidra Python Script — Generated by Memory Inspector\n";
  f << "# Run in Ghidra: Script Manager → Run Script\n";
  f << "# NOTE: Adjust IMAGE_BASE to match Ghidra's Image Base\n\n";
  f << "from ghidra.program.model.symbol import SourceType\n\n";

  // Determine image base from first module in map_entries
  uintptr_t runtime_base = 0;
  std::string main_module = "???";
  if (!map_entries.empty()) {
    // Find first executable region (likely the main binary)
    for (const auto &e : map_entries) {
      if (e.is_code && !e.is_heap && !e.is_stack && e.module != "[anonymous]") {
        runtime_base = e.start;
        main_module = e.module;
        break;
      }
    }
  }

  f << "RUNTIME_BASE = " << std::hex << "0x" << runtime_base << "\n";
  f << "# Main module detected: " << main_module << "\n\n";

  f << "def label(offset, name):\n";
  f << "    ghidra_base = currentProgram.getImageBase().getOffset()\n";
  f << "    addr = toAddr(ghidra_base + offset)\n";
  f << "    createLabel(addr, name, True, SourceType.USER_DEFINED)\n\n";

  f << "# ── Found scan results ──\n";
  for (const auto &res : categorized_results) {
    std::string val = scanner.read_value_str(res.addr);
    uint64_t offset = res.addr - res.base_addr;
    std::ostringstream ss;
    ss << std::hex << std::uppercase << offset;
    f << "label(0x" << ss.str() << ", \"var_" << ss.str() << "\")"
      << "  # module=" << res.module_name << " val=" << val
      << " type=" << valueTypeName(scanner.get_value_type()) << "\n";
  }

  f << "\n# ── Call graph functions ──\n";
  for (const auto &node : call_graph) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << node.offset;
    f << "label(0x" << ss.str() << ", \"" << node.name << "\")"
      << "  # depth=" << node.depth << " module=" << node.module << "\n";
  }

  f.close();
  add_log("✓ Ghidra script → " + path);
}
