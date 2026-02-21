// ═══════════════════════════════════════════════════════════════════════
//  TUI::run() — main UI, appended to TUI.cpp
// ═══════════════════════════════════════════════════════════════════════
#include "KittyGraphics.hpp"
#include "TUI.hpp"
#include "ftxui/component/component_options.hpp"
#include "ftxui/component/event.hpp"
#include "ftxui/dom/canvas.hpp"
#include "ftxui/dom/elements.hpp"
#include "ftxui/screen/color.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <keystone/keystone.h>
#include <sstream>
#include <thread>
using namespace ftxui;

void TUI::run() {
  const auto C_BG = Color::RGB(8, 8, 14);
  const auto C_FG = Color::RGB(200, 200, 220);
  const auto C_ACCENT = Color::RGB(80, 160, 255);
  const auto C_ACCENT2 = Color::RGB(140, 80, 255);
  const auto C_GREEN = Color::RGB(50, 230, 120);
  const auto C_RED = Color::RGB(255, 70, 70);
  const auto C_ORANGE = Color::RGB(255, 170, 50);
  const auto C_CYAN = Color::RGB(50, 220, 220);
  const auto C_DIM = Color::RGB(90, 90, 110);
  const auto C_YELLOW = Color::RGB(255, 220, 50);
  const auto C_SEL_BG = Color::RGB(30, 50, 90);

  auto input_pid = Input(&pid_input, "PID...");
  auto input_scan = Input(&scan_value, "value...");
  auto input_next =
      Input(&next_scan_value, "value (blank for relative scans)...");
  auto input_write = Input(&write_value_input, "new value...");
  auto input_goto_a = Input(&goto_addr_input, "0x... or decimal...");
  auto input_ghidra_base = Input(&ghidra_base_input, "0x... or decimal...");
  std::string patch_hex_input;
  auto input_patch_hex = Input(&patch_hex_input, "e.g. 90 90");
  auto input_watch_desc = Input(&watch_desc_input, "Description...");
  auto input_struct_base = Input(&struct_base_addr_input, "0x...");
  auto input_speedhack = Input(&speedhack_input, "2.0 or 0.5...");

  auto hex_str = [](uintptr_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << v;
    return s.str();
  };

  auto do_set_ghidra_base = [&] {
    try {
      uintptr_t base = 0;
      if (ghidra_base_input.size() > 2 && ghidra_base_input[0] == '0' &&
          (ghidra_base_input[1] == 'x' || ghidra_base_input[1] == 'X'))
        base = std::stoull(ghidra_base_input, nullptr, 16);
      else
        base = std::stoull(ghidra_base_input, nullptr, 10);
      ghidra_image_base = base;
      add_log("✓ Ghidra ImageBase set to " + hex_str(base));
    } catch (...) {
      add_log("✗ Invalid Ghidra base");
    }
    show_ghidra_base_modal = false;
    ghidra_base_input.clear();
  };

  auto do_attach = [&] {
    try {
      if (engine.attach(std::stoi(pid_input))) {
        add_log("✓ Attached " + pid_input);
        update_memory_map();
      } else
        add_log("✗ Failed " + pid_input);
    } catch (...) {
      add_log("✗ Bad PID");
    }
    show_attach_modal = false;
  };

  auto do_initial_scan = [&] {
    scanner.initial_scan(VALUE_TYPES[selected_value_type_idx], scan_value);
    add_log("✓ Scan [" +
            std::string(VALUE_TYPE_NAMES[selected_value_type_idx]) + "] → " +
            std::to_string(scanner.get_results().size()) + " results");
    show_scan_modal = false;
  };

  auto do_next_scan = [&] {
    scanner.next_scan(SCAN_TYPES[selected_scan_type_idx], next_scan_value);
    add_log("✓ Next [" + std::string(SCAN_TYPE_NAMES[selected_scan_type_idx]) +
            "] → " + std::to_string(scanner.get_results().size()) + " results");
    show_next_scan_modal = false;
  };

  auto do_write = [&] {
    if (tracked_address) {
      if (scanner.write_value(tracked_address, write_value_input))
        add_log("✓ Wrote " + write_value_input + " → " +
                hex_str(tracked_address));
      else
        add_log("✗ Write failed");
    }
    show_write_modal = false;
    write_value_input.clear();
  };

  auto do_goto_action = [&] {
    try {
      uintptr_t addr = 0;
      if (goto_addr_input.size() > 2 && goto_addr_input[0] == '0' &&
          (goto_addr_input[1] == 'x' || goto_addr_input[1] == 'X'))
        addr = std::stoull(goto_addr_input, nullptr, 16);
      else
        addr = std::stoull(goto_addr_input, nullptr, 10);
      tracked_address = addr;
      hex_dump.resize(128, 0);
      engine.read_memory(addr, hex_dump.data(), 128);
      if (show_disasm)
        update_disasm();
      add_log("→ Jumped to " + hex_str(addr));
    } catch (...) {
      add_log("✗ Invalid address");
    }
    show_goto_modal = false;
    goto_addr_input.clear();
  };

  auto do_add_watch = [&] {
    if (tracked_address) {
      WatchEntry we;
      we.addr = tracked_address;
      we.description =
          watch_desc_input.empty() ? "No description" : watch_desc_input;
      we.type = scanner.get_value_type();
      we.frozen = false;
      watchlist.push_back(std::move(we));
      add_log("✓ Added to Watchlist: " + hex_str(tracked_address));
    }
    show_watch_modal = false;
    watch_desc_input.clear();
  };

  auto do_ptr_scan = [&] {
    if (tracked_address) {
      add_log("Pointer Scan for " + hex_str(tracked_address) + "...");
      ptr_results = scanner.find_pointers(tracked_address, 2, 1024);
      add_log("✓ Found " + std::to_string(ptr_results.size()) +
              " pointer paths");
      main_tab = 4;
    } else
      add_log("✗ No address");
    show_ptr_modal = false;
  };

  // ──────────────────────────────────────────────────────────────────
  // ADDRESS TAB
  // ──────────────────────────────────────────────────────────────────
  auto address_tab = Renderer([&] {
    Elements lines;
    static uint32_t fc = 0;
    fc++;
    int actual = 0;
    for (int i = 0; i < (int)categorized_results.size(); ++i) {
      const auto &res = categorized_results[i];
      if (hide_suspicious_low && res.suspicious_score < 30)
        continue;
      std::string vs = scanner.read_value_str(res.addr);
      double dv = read_as_double(res.addr);
      Color cv = C_FG;
      if (last_vals_for_color.count(res.addr)) {
        double pv = last_vals_for_color[res.addr];
        if (dv > pv)
          cv = C_RED;
        else if (dv < pv)
          cv = C_ACCENT;
      }
      if (fc % 3 == 0)
        last_vals_for_color[res.addr] = dv;
      std::ostringstream sa, so;
      sa << "0x" << std::hex << std::uppercase << std::setw(12)
         << std::setfill('0') << res.addr;
      so << std::hex << std::uppercase << (res.addr - res.base_addr);
      bool frz = frozen_addresses.count(res.addr);
      Color cc = C_DIM;
      switch (res.type) {
      case AddressType::Code:
        cc = C_RED;
        break;
      case AddressType::Data:
        cc = C_ORANGE;
        break;
      case AddressType::Heap:
        cc = C_GREEN;
        break;
      case AddressType::Stack:
        cc = C_ACCENT;
        break;
      default:
        break;
      }
      auto row = hbox(
          text(frz ? "❄" : " ") | color(C_CYAN),
          text("[" + addr_type_str(res.type) + "]") | color(cc) | bold,
          text(" "),
          text(sa.str()) | color(res.suspicious_score > 50 ? C_FG : C_DIM) |
              size(WIDTH, EQUAL, 16),
          text(" +") | color(C_DIM),
          text(so.str()) | color(C_ACCENT2) | size(WIDTH, EQUAL, 10),
          text(" │ ") | color(C_DIM),
          text("[" + valueTypeName(scanner.get_value_type()) + "]") |
              color(C_ACCENT2) | size(WIDTH, EQUAL, 9),
          text(" "), text(vs) | color(cv) | bold | size(WIDTH, EQUAL, 14));
      if (actual == selected_result_idx)
        row = row | bgcolor(C_SEL_BG) | color(Color::White);
      lines.push_back(row);
      actual++;
    }
    int vs2 = std::max(0, selected_result_idx - 12),
        ve = std::min((int)lines.size(), vs2 + 28);
    Elements vis;
    for (int i = vs2; i < ve; ++i)
      vis.push_back(lines[i]);
    return vbox(std::move(vis));
  });

  // ──────────────────────────────────────────────────────────────────
  // MEMORY MAP TAB
  // ──────────────────────────────────────────────────────────────────
  auto memmap_tab = Renderer([&] {
    if (map_entries.empty())
      return text(" No map. Attach a PID. ") | color(C_DIM);
    Elements rows;
    rows.push_back(hbox(text(" START            ") | color(C_DIM) | bold,
                        text(" END              ") | color(C_DIM) | bold,
                        text(" SIZE      ") | color(C_DIM) | bold,
                        text(" PERMS ") | color(C_DIM) | bold,
                        text(" MODULE") | color(C_DIM) | bold) |
                   bgcolor(Color::RGB(20, 20, 35)));
    rows.push_back(separatorLight() | color(C_DIM));
    int vs2 = std::max(0, selected_map_idx - 15),
        ve = std::min((int)map_entries.size(), vs2 + 35);
    for (int i = vs2; i < ve; ++i) {
      const auto &e = map_entries[i];
      std::ostringstream ss, se, sz;
      ss << "0x" << std::hex << std::uppercase << std::setw(14)
         << std::setfill('0') << e.start;
      se << "0x" << std::hex << std::uppercase << std::setw(14)
         << std::setfill('0') << e.end;
      size_t kb = e.size_bytes / 1024;
      if (kb > 1024)
        sz << (kb / 1024) << " MB";
      else
        sz << kb << " KB";
      Color mc = C_FG;
      if (e.is_code)
        mc = Color::RGB(255, 120, 120);
      else if (e.is_heap)
        mc = Color::RGB(100, 255, 150);
      else if (e.is_stack)
        mc = Color::RGB(100, 150, 255);
      else if (e.module != "[anonymous]")
        mc = C_YELLOW;
      auto row = hbox(
          text(" " + ss.str() + " ") | color(C_DIM),
          text(" " + se.str() + " ") | color(C_DIM),
          text(" " + sz.str() + " ") | color(C_ACCENT) | size(WIDTH, EQUAL, 10),
          text(" " + e.perms + " ") | color(e.is_code ? C_RED : C_DIM) |
              size(WIDTH, EQUAL, 6),
          text(" " + e.module) | color(mc) | bold);
      if (i == selected_map_idx)
        row = row | bgcolor(C_SEL_BG) | color(Color::White);
      rows.push_back(row);
    }
    return vbox(std::move(rows));
  });

  // ──────────────────────────────────────────────────────────────────
  // CALL GRAPH TAB
  // ──────────────────────────────────────────────────────────────────
  auto callgraph_tab = Renderer([&] {
    if (call_graph.empty()) {
      Elements h;
      h.push_back(text(" No call graph data. ") | color(C_DIM));
      h.push_back(text(" Select an address in Addresses tab, then press B.") |
                  color(C_DIM));
      return vbox(std::move(h));
    }
    Elements rows;
    rows.push_back(
        hbox(text(" D") | color(C_DIM) | bold | size(WIDTH, EQUAL, 3),
             text(" ADDRESS       ") | color(C_DIM) | bold |
                 size(WIDTH, EQUAL, 16),
             text(" +OFFSET   ") | color(C_DIM) | bold | size(WIDTH, EQUAL, 12),
             text(" MODULE       ") | color(C_DIM) | bold |
                 size(WIDTH, EQUAL, 16),
             text(" HEURISTIC NAME") | color(C_DIM) | bold) |
        bgcolor(Color::RGB(20, 20, 35)));
    rows.push_back(separatorLight() | color(C_DIM));
    int vs2 = std::max(0, selected_cg_idx - 15),
        ve = std::min((int)call_graph.size(), vs2 + 32);
    for (int i = vs2; i < ve; ++i) {
      const auto &n = call_graph[i];
      std::string ind(n.depth * 2, ' ');
      std::ostringstream sa, so;
      sa << "0x" << std::hex << std::uppercase << n.addr;
      so << "+" << std::hex << std::uppercase << n.offset;
      Color nc = (n.depth == 0) ? C_YELLOW : n.is_external ? C_RED : C_GREEN;
      auto row =
          hbox(text(" " + std::to_string(n.depth)) | color(C_DIM) |
                   size(WIDTH, EQUAL, 3),
               text(" " + sa.str()) | color(C_CYAN) | size(WIDTH, EQUAL, 16),
               text(" " + so.str()) | color(C_ACCENT2) | size(WIDTH, EQUAL, 12),
               text(" " + n.module) | color(C_ORANGE) | size(WIDTH, EQUAL, 16),
               text(" " + ind + n.name) | color(nc) | bold);
      if (i == selected_cg_idx)
        row = row | bgcolor(C_SEL_BG) | color(Color::White);
      rows.push_back(row);
    }
    rows.push_back(separatorLight() | color(C_DIM));
    rows.push_back(
        hbox(text(" Nodes: ") | color(C_DIM),
             text(std::to_string(call_graph.size())) | color(C_ACCENT) | bold,
             text("  [B]rebuild  [E]export to Ghidra") | color(C_DIM)));
    return vbox(std::move(rows));
  });

  // ──────────────────────────────────────────────────────────────────
  // WATCHLIST TAB
  // ──────────────────────────────────────────────────────────────────
  auto watch_tab = Renderer([&] {
    if (watchlist.empty())
      return text(" Watchlist empty. [A] to add current address. ") |
             color(C_DIM) | center;
    Elements rows;
    rows.push_back(hbox(text(" DESCRIPTION      ") | color(C_DIM) | bold,
                        text(" ADDRESS          ") | color(C_DIM) | bold,
                        text(" TYPE      ") | color(C_DIM) | bold,
                        text(" VALUE            ") | color(C_DIM) | bold) |
                   bgcolor(Color::RGB(20, 20, 35)));
    rows.push_back(separatorLight() | color(C_DIM));
    for (int i = 0; i < (int)watchlist.size(); ++i) {
      auto &we = watchlist[i];
      auto row = hbox(text(" " + we.description) | size(WIDTH, EQUAL, 18),
                      text(" " + hex_str(we.addr)) | color(C_CYAN) |
                          size(WIDTH, EQUAL, 18),
                      text(" " + valueTypeName(we.type)) | color(C_ACCENT2) |
                          size(WIDTH, EQUAL, 10),
                      text(" " + we.cached_val) | color(C_GREEN) | bold);
      if (i == selected_watch_idx)
        row = row | bgcolor(C_SEL_BG);
      rows.push_back(row);
    }
    return vbox(std::move(rows));
  });

  // ──────────────────────────────────────────────────────────────────
  // POINTER SCAN TAB
  // ──────────────────────────────────────────────────────────────────
  auto ptr_tab = Renderer([&] {
    if (ptr_results.empty())
      return text(" No pointer results. [P] to scan current address. ") |
             color(C_DIM) | center;
    Elements rows;
    rows.push_back(hbox(text(" MODULE           ") | color(C_DIM) | bold,
                        text(" BASE ADDR        ") | color(C_DIM) | bold,
                        text(" OFFSETS          ") | color(C_DIM) | bold) |
                   bgcolor(Color::RGB(20, 20, 35)));
    rows.push_back(separatorLight() | color(C_DIM));
    for (int i = 0; i < (int)ptr_results.size(); ++i) {
      auto &p = ptr_results[i];
      std::string off_str;
      for (auto o : p.offsets)
        off_str += (o >= 0 ? "+" : "") + std::to_string(o) + " ";
      auto row = hbox(
          text(" " + p.module_name) | color(C_ORANGE) | size(WIDTH, EQUAL, 18),
          text(" " + hex_str(p.base_module_addr)) | size(WIDTH, EQUAL, 18),
          text(" " + off_str) | color(C_YELLOW));
      if (i == selected_ptr_idx)
        row = row | bgcolor(C_SEL_BG);
      rows.push_back(row);
    }
    return vbox(std::move(rows));
  });

  // ──────────────────────────────────────────────────────────────────
  // DISASSEMBLER TAB
  // ──────────────────────────────────────────────────────────────────
  auto disasm_tab_r = Renderer([&] {
    if (disasm_lines.empty())
      return text(" ERR: No disassembly available here. ") | color(C_RED) |
             center;
    Elements rows;
    rows.push_back(hbox(text(" ADDRESS          ") | color(C_DIM) | bold,
                        text(" BYTES                 ") | color(C_DIM) | bold,
                        text(" INSTRUCTION ") | color(C_DIM) | bold) |
                   bgcolor(Color::RGB(20, 20, 35)));
    rows.push_back(separatorLight() | color(C_DIM));

    int start_idx = std::max(0, selected_disasm_idx - 15);
    for (int i = start_idx;
         i < std::min((int)disasm_lines.size(), start_idx + 35); ++i) {
      auto &l = disasm_lines[i];
      Color mc = C_ORANGE;
      if (!l.mnem.empty()) {
        char c0 = l.mnem[0];
        if (c0 == 'j' || l.mnem == "call")
          mc = C_RED;
        else if (l.mnem == "mov" || l.mnem == "lea")
          mc = C_CYAN;
        else if (l.mnem == "push" || l.mnem == "pop")
          mc = C_ACCENT2;
        else if (l.mnem == "ret")
          mc = C_GREEN;
        else if (l.mnem == "nop")
          mc = C_DIM;
      }
      std::ostringstream ss;
      ss << "0x" << std::hex << std::uppercase << l.addr;
      bool is_node = cg_index.count(l.addr) > 0;

      auto row = hbox(text(ss.str() + " ") | color(is_node ? C_YELLOW : C_DIM) |
                          size(WIDTH, EQUAL, 18),
                      text(l.bytes_hex) | color(C_DIM) | size(WIDTH, EQUAL, 23),
                      text(" "),
                      text(l.mnem) | color(mc) | bold | size(WIDTH, EQUAL, 8),
                      text(l.ops) | color(is_node ? C_YELLOW : C_FG));

      if (i == selected_disasm_idx)
        row = row | bgcolor(C_SEL_BG);
      rows.push_back(row);
    }
    return vbox(std::move(rows));
  });

  // ──────────────────────────────────────────────────────────────────
  // STRUCTURE DISSECTOR TAB
  // ──────────────────────────────────────────────────────────────────
  auto struct_tab_r = Renderer(input_struct_base, [&] {
    uintptr_t base = 0;
    if (!struct_base_addr_input.empty()) {
      try {
        if (struct_base_addr_input.find("0x") == 0)
          base = std::stoull(struct_base_addr_input, nullptr, 16);
        else
          base = std::stoull(struct_base_addr_input, nullptr, 10);
      } catch (...) {
      }
    } else {
      base = tracked_address;
    }

    Elements rows;
    rows.push_back(hbox(text(" Base Addr: ") | color(C_DIM),
                        input_struct_base->Render() | size(WIDTH, EQUAL, 20)));
    rows.push_back(separatorLight() | color(C_DIM));
    rows.push_back(
        hbox(text(" OFFSET ") | bold | color(C_DIM) | size(WIDTH, EQUAL, 9),
             text(" HEX         ") | bold | color(C_DIM) |
                 size(WIDTH, EQUAL, 14),
             text(" INT32       ") | bold | color(C_DIM) |
                 size(WIDTH, EQUAL, 14),
             text(" FLOAT       ") | bold | color(C_DIM) |
                 size(WIDTH, EQUAL, 14),
             text(" STRING") | bold | color(C_DIM)) |
        bgcolor(Color::RGB(20, 20, 35)));
    rows.push_back(separatorLight() | color(C_DIM));

    if (base) {
      std::vector<uint8_t> buf(128, 0);
      engine.read_memory(base, buf.data(), 128);
      for (int i = 0; i < 128; i += 4) {
        std::ostringstream os, hs, is, fs;
        os << "+" << std::hex << std::uppercase << std::setfill('0')
           << std::setw(2) << i;
        hs << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
           << (int)buf[i] << " " << std::setw(2) << (int)buf[i + 1] << " "
           << std::setw(2) << (int)buf[i + 2] << " " << std::setw(2)
           << (int)buf[i + 3];
        int32_t iv;
        std::memcpy(&iv, &buf[i], 4);
        is << iv;
        float fv;
        std::memcpy(&fv, &buf[i], 4);
        if (std::abs(fv) > 1e-10 && std::abs(fv) < 1e10)
          fs << std::fixed << std::setprecision(3) << fv;
        else
          fs << "---";

        std::string strv;
        for (int j = 0; j < 4; ++j) {
          char c = buf[i + j];
          if (c >= 0x20 && c < 0x7F)
            strv += c;
          else
            strv += ".";
        }

        rows.push_back(hbox(
            text(" " + os.str()) | color(C_ACCENT2) | size(WIDTH, EQUAL, 9),
            text(" " + hs.str()) | color(C_CYAN) | size(WIDTH, EQUAL, 14),
            text(" " + is.str()) | color(C_YELLOW) | size(WIDTH, EQUAL, 14),
            text(" " + fs.str()) | color(C_GREEN) | size(WIDTH, EQUAL, 14),
            text(" " + strv) | color(C_FG)));
      }
    } else {
      rows.push_back(text(" Provide base address to dissect ") | color(C_DIM) |
                     center);
    }
    return vbox(std::move(rows));
  });

  // ──────────────────────────────────────────────────────────────────
  // HEX / DISASM + GRAPH
  // ──────────────────────────────────────────────────────────────────
  auto hex_view = Renderer([&] {
    if (show_disasm) {
      Elements lines;
      for (auto &l : disasm_lines) {
        Color mc = C_ORANGE;
        if (!l.mnem.empty()) {
          char c0 = l.mnem[0];
          if (c0 == 'j' || l.mnem == "call")
            mc = C_RED;
          else if (l.mnem == "mov" || l.mnem == "lea")
            mc = C_CYAN;
          else if (l.mnem == "push" || l.mnem == "pop")
            mc = C_ACCENT2;
          else if (l.mnem == "ret")
            mc = C_GREEN;
          else if (l.mnem == "nop")
            mc = C_DIM;
        }
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << l.addr;
        bool is_node = cg_index.count(l.addr) > 0;
        lines.push_back(hbox(
            text(ss.str()) | color(is_node ? C_YELLOW : C_DIM) |
                size(WIDTH, EQUAL, 16),
            text("  "), text(l.mnem) | color(mc) | bold | size(WIDTH, EQUAL, 8),
            text(l.ops) | color(is_node ? C_YELLOW : C_FG)));
      }
      return vbox(std::move(lines));
    }
    Elements rows;
    for (int i = 0; i < 8; ++i) {
      Elements cols;
      std::ostringstream as;
      as << "0x" << std::hex << std::uppercase << std::setw(6)
         << std::setfill('0') << (tracked_address + i * 16);
      cols.push_back(text(as.str() + "  ") | color(C_DIM));
      for (int j = 0; j < 16; ++j) {
        int idx = i * 16 + j;
        if (idx < (int)hex_dump.size()) {
          std::ostringstream bs;
          bs << std::setw(2) << std::setfill('0') << std::hex << std::uppercase
             << (int)hex_dump[idx];
          Color bc = C_FG;
          if (hex_dump[idx] == 0)
            bc = C_DIM;
          else if (hex_dump[idx] == 0xFF)
            bc = C_RED;
          else if (hex_dump[idx] >= 0x20 && hex_dump[idx] < 0x7F)
            bc = C_GREEN;
          cols.push_back(text(bs.str() + " ") | color(bc));
        }
      }
      cols.push_back(text("│") | color(C_DIM));
      for (int j = 0; j < 16; ++j) {
        int idx = i * 16 + j;
        if (idx < (int)hex_dump.size()) {
          char ch = (hex_dump[idx] >= 0x20 && hex_dump[idx] < 0x7F)
                        ? (char)hex_dump[idx]
                        : '.';
          cols.push_back(text(std::string(1, ch)) |
                         color(ch == '.' ? C_DIM : C_CYAN));
        }
      }
      rows.push_back(hbox(std::move(cols)));
    }
    return vbox(std::move(rows));
  });

  auto graph_view = Renderer([&] {
    return canvas([&](Canvas &c) {
             if (value_history.size() < 2)
               return;
             float mn =
                 *std::min_element(value_history.begin(), value_history.end());
             float mx =
                 *std::max_element(value_history.begin(), value_history.end());
             float rng = (mx - mn > 0) ? (mx - mn) : 1.0f;
             int H = 38;
             for (size_t i = 1; i < value_history.size(); ++i) {
               int y1 = H - (int)((value_history[i - 1] - mn) / rng * H);
               int y2 = H - (int)((value_history[i] - mn) / rng * H);
               c.DrawBlockLine((int)(i - 1) * 2, y1, (int)i * 2, y2, C_GREEN);
             }
             std::ostringstream smx, smn;
             smx << (int)mx;
             smn << (int)mn;
             c.DrawText(0, 0, smx.str());
             c.DrawText(0, H, smn.str());
           }) |
           color(C_GREEN);
  });

  auto log_view = Renderer([&] {
    Elements l;
    int s = std::max(0, (int)logs.size() - 6);
    for (int i = s; i < (int)logs.size(); ++i)
      l.push_back(text(logs[i]) | color(C_DIM));
    return vbox(std::move(l));
  });

  // ──────────────────────────────────────────────────────────────────
  // SIDEBAR
  // ──────────────────────────────────────────────────────────────────
  auto sidebar_view = Renderer([&] {
    bool hp = (engine.get_pid() != -1);
    auto mk_tab = [&](int idx, const std::string &label) {
      bool sel = (main_tab == idx);
      return text(" " + label + " ") | (sel ? bold : dim) |
             color(sel ? Color::White : C_DIM) |
             (sel ? bgcolor(C_SEL_BG) : bgcolor(Color::Default));
    };
    Elements sb;
    sb.push_back(hbox(text("◉") | color(hp ? C_GREEN : C_RED),
                      text(" PID ") | color(C_DIM),
                      text(hp ? std::to_string(engine.get_pid()) : "---") |
                          color(hp ? C_GREEN : C_RED) | bold) |
                 borderLight);
    sb.push_back(
        vbox(text(" TABS ") | bold | color(C_ACCENT2) | hcenter,
             hbox(mk_tab(0, "Addr"), mk_tab(1, "Map"), mk_tab(2, "CG"),
                  mk_tab(3, "Watch")) |
                 hcenter,
             hbox(mk_tab(4, "Ptr"), mk_tab(5, "Disasm"), mk_tab(6, "Struct")) |
                 hcenter,
             text(" [Tab] switch ") | color(C_DIM) | hcenter) |
        borderLight);
    sb.push_back(
        vbox(
            text(" SCAN ") | bold | color(C_ACCENT2) | hcenter,
            text(" Results: " + std::to_string(scanner.get_results().size())) |
                color(C_ACCENT),
            hbox(text(" Type: ") | color(C_DIM),
                 text(VALUE_TYPE_NAMES[selected_value_type_idx]) |
                     color(C_CYAN) | bold),
            hbox(text(" Mode: ") | color(C_DIM),
                 text(SCAN_TYPE_NAMES[selected_scan_type_idx]) | color(C_CYAN)),
            text(" [T]type [Y]mode") | color(C_DIM)) |
        borderLight);
    sb.push_back(vbox(text(" ACTIONS ") | bold | color(C_ACCENT) | hcenter,
                      text(" F2 First Scan") | color(C_FG),
                      text(" F7 Next Scan") | color(C_FG),
                      text(" F8 Clear") | color(C_FG),
                      text(" W  Write Value") | color(C_ORANGE),
                      text(" G  Go-to Addr") | color(C_YELLOW),
                      text(" B  Build CG") | color(C_GREEN),
                      text(" P  Pointer Scan") | color(C_YELLOW) | bold,
                      text(" A  Add to Watch") | color(C_ACCENT) | bold,
                      text(" E  Ghidra Exp") | color(C_ACCENT2),
                      text(" F10 Speedhack") | color(C_YELLOW) | bold,
                      text(" F5 Freeze") | color(C_CYAN),
                      text(" F3 Hex/Asm") | color(C_DIM),
                      text(" F4 Attach") | color(C_DIM),
                      text(" F1 Help") | color(C_DIM),
                      text(" Q  Quit") | color(C_RED)) |
                 borderLight);

    if (tracked_address && !categorized_results.empty()) {
      CategorizedAddress ri = {};
      if (selected_result_idx < (int)categorized_results.size())
        ri = categorized_results[selected_result_idx];
      std::ostringstream sa, so;
      sa << "0x" << std::hex << std::uppercase << tracked_address;
      so << "0x" << std::hex << std::uppercase
         << (tracked_address - ri.base_addr);
      bool frz = frozen_addresses.count(tracked_address);

      // Is it a file-backed module?
      bool is_mappable =
          (ri.module_name != "[stack]" && ri.module_name != "[heap]" &&
           ri.module_name != "[anonymous]" && !ri.module_name.empty());

      Elements info;
      info.push_back(text(" SELECTED ") | bold | color(C_ACCENT2) | hcenter);
      info.push_back(text(" " + sa.str()) | color(C_CYAN) | hcenter);
      info.push_back(
          hbox(text(" Mod: ") | color(C_DIM),
               text(ri.module_name) | color(is_mappable ? C_GREEN : C_RED)));
      info.push_back(hbox(text(" Off: ") | color(C_DIM),
                          text(so.str()) | color(C_ACCENT)));
      info.push_back(hbox(text(" Typ: ") | color(C_DIM),
                          text(valueTypeName(scanner.get_value_type())) |
                              color(C_ORANGE)));
      info.push_back(hbox(text(" Val: ") | color(C_DIM),
                          text(scanner.read_value_str(tracked_address)) |
                              color(C_GREEN) | bold));
      info.push_back(
          hbox(text(" Frz: ") | color(C_DIM),
               text(frz ? "❄YES" : "NO") | color(frz ? C_CYAN : C_DIM)));
      info.push_back(separatorLight() | color(C_DIM));

      if (is_mappable) {
        uintptr_t ghidra_addr = ghidra_image_base + ri.file_offset +
                                (tracked_address - ri.base_addr);
        std::ostringstream sga;
        sga << "0x" << std::hex << std::uppercase << ghidra_addr;
        std::string ghidra_str = sga.str();

        // Auto-save to /tmp for easy copy with: cat /tmp/ghidra_addr.txt
        {
          std::ofstream gf("/tmp/ghidra_addr.txt");
          gf << ghidra_str << "\n";
          gf << "# offset=" << so.str() << " module=" << ri.module_name << "\n";
          gf << "# base=0x" << std::hex << ghidra_image_base << "\n";
        }

        info.push_back(separatorLight() | color(C_DIM));
        info.push_back(text(" ► GHIDRA ADDR ") | bold |
                       bgcolor(Color::RGB(40, 30, 0)) | color(C_YELLOW) |
                       hcenter);
        info.push_back(text(" " + ghidra_str) | color(C_YELLOW) | bold |
                       hcenter);
        info.push_back(separatorLight() | color(C_DIM));
        info.push_back(hbox(text(" off: ") | color(C_DIM),
                            text(so.str()) | color(C_ORANGE) | bold));
        info.push_back(
            hbox(text(" base:") | color(C_DIM),
                 text("0x" + hex_str(ghidra_image_base)) | color(C_DIM)));
        info.push_back(text(" → cat /tmp/ghidra_addr.txt") | color(C_DIM));
      } else {
        info.push_back(separatorLight() | color(C_DIM));
        info.push_back(text(" ⚠ DYNAMIC REGION ") | color(C_RED) | bold |
                       hcenter);
        info.push_back(text(" Stack/Heap/Anon ") | dim | hcenter);
        info.push_back(text(" No static addr ") | dim | hcenter);
      }
      sb.push_back(vbox(std::move(info)) | borderLight);
    }
    sb.push_back(hbox(text(" F9 ") | bold | color(C_ACCENT),
                      text(" Set Ghidra Base") | dim));
    sb.push_back(filler());
    return vbox(std::move(sb));
  });

  // ──────────────────────────────────────────────────────────────────
  // MAIN LAYOUT
  // ──────────────────────────────────────────────────────────────────
  auto main_layout = Renderer([&]() -> Element {
    bool hp = engine.get_pid() != -1;
    auto header =
        hbox(text(" ⬡ IxeRam ") | bold | color(C_ACCENT), filler(),
             text(hp ? " PID " + std::to_string(engine.get_pid()) + " "
                     : " OFFLINE ") |
                 color(hp ? C_GREEN : C_RED) | bold,
             text(" │ ") | color(C_DIM),
             text(std::to_string(scanner.get_results().size()) + " results") |
                 color(C_ACCENT),
             text(" │ ") | color(C_DIM),
             text(main_tab == 0   ? "[Addr]"
                  : main_tab == 1 ? "[Map]"
                  : main_tab == 2 ? "[CGraph]"
                  : main_tab == 3 ? "[Watch]"
                  : main_tab == 4 ? "[Ptr]"
                                  : "[Disasm]") |
                 color(C_YELLOW) | bold) |
        bgcolor(Color::RGB(15, 15, 25)) | borderLight;

    Element center;
    if (main_tab == 0) {
      center =
          vbox(window(hbox(text(" ◈ ADDRESSES "), filler(),
                           text(hide_suspicious_low ? "[FILTERED]" : "[ALL]") |
                               color(C_DIM)),
                      address_tab->Render()) |
                   flex,
               window(text(" ◈ LOG "), log_view->Render()) |
                   size(HEIGHT, EQUAL, 8)) |
          flex;
    } else if (main_tab == 1) {
      center = vbox(window(hbox(text(" ◈ MEMORY MAP "), filler(),
                                text(std::to_string(map_entries.size()) +
                                     " regions") |
                                    color(C_DIM)),
                           memmap_tab->Render()) |
                        flex,
                    window(text(" ◈ LOG "), log_view->Render()) |
                        size(HEIGHT, EQUAL, 8)) |
               flex;
    } else if (main_tab == 2) {
      center = vbox(window(hbox(text(" ◈ CALL GRAPH "), filler(),
                                text("[B]build [E]export") | color(C_DIM)),
                           callgraph_tab->Render()) |
                        flex,
                    window(text(" ◈ LOG "), log_view->Render()) |
                        size(HEIGHT, EQUAL, 8)) |
               flex;
    } else if (main_tab == 3) {
      center =
          vbox(window(hbox(text(" ◈ WATCHLIST "), filler(),
                           text(std::to_string(watchlist.size()) + " items") |
                               color(C_DIM)),
                      watch_tab->Render()) |
                   flex,
               window(text(" ◈ LOG "), log_view->Render()) |
                   size(HEIGHT, EQUAL, 8)) |
          flex;
    } else if (main_tab == 4) {
      center =
          vbox(window(hbox(text(" ◈ POINTER SCAN "), filler(),
                           text(std::to_string(ptr_results.size()) + " paths") |
                               color(C_DIM)),
                      ptr_tab->Render()) |
                   flex,
               window(text(" ◈ LOG "), log_view->Render()) |
                   size(HEIGHT, EQUAL, 8)) |
          flex;
    } else if (main_tab == 5) {
      center =
          vbox(window(hbox(text(" ◈ DISASSEMBLER / MEMORY VIEWER "), filler(),
                           text("[SPACE]patch [ENTER]jump [BACKSPACE]back") |
                               color(C_DIM)),
                      disasm_tab_r->Render()) |
                   flex,
               window(text(" ◈ LOG "), log_view->Render()) |
                   size(HEIGHT, EQUAL, 8)) |
          flex;
    } else {
      center = vbox(window(hbox(text(" ◈ STRUCTURE DISSECTOR "), filler()),
                           struct_tab_r->Render()) |
                        flex,
                    window(text(" ◈ LOG "), log_view->Render()) |
                        size(HEIGHT, EQUAL, 8)) |
               flex;
    }

    auto right = vbox(window(text(show_disasm ? " ◈ DISASM " : " ◈ HEX "),
                             hex_view->Render()) |
                          flex,
                      window(text(" ◈ GRAPH "), graph_view->Render()) |
                          size(HEIGHT, EQUAL, 14)) |
                 flex;

    auto footer =
        hbox(text(" F2:Scan") | color(C_GREEN), text("|") | color(C_DIM),
             text("F7:Next") | color(C_ACCENT), text("|") | color(C_DIM),
             text("W:Write") | color(C_ORANGE), text("|") | color(C_DIM),
             text("G:Goto") | color(C_YELLOW), text("|") | color(C_DIM),
             text("B:CGraph") | color(C_GREEN), text("|") | color(C_DIM),
             text("E:Export") | color(C_ACCENT2), text("|") | color(C_DIM),
             text("F5:Freeze") | color(C_CYAN), text("|") | color(C_DIM),
             text("Tab:Tab") | color(C_DIM), text("|") | color(C_DIM),
             text("Q:Quit") | color(C_RED), filler(),
             text(" IxeRam - made by Internium Entertainment ") |
                 color(C_DIM)) |
        bgcolor(Color::RGB(12, 12, 22));

    return vbox(header,
                hbox(sidebar_view->Render() | size(WIDTH, EQUAL, 32),
                     separator() | color(C_DIM), center,
                     separator() | color(C_DIM), right) |
                    flex,
                footer) |
           bgcolor(C_BG) | color(C_FG);
  });

  // ──────────────────────────────────────────────────────────────────
  // MODALS
  // ──────────────────────────────────────────────────────────────────
  auto patch_modal_r = Renderer(input_patch_hex, [&] {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << patch_addr;
    return vbox(text(" ◈ PATCH INSTRUCTION ") | bold | color(C_RED) | hcenter,
                separatorDouble(), text(" Addr: " + ss.str()) | color(C_CYAN),
                text(" Enter hex bytes (e.g. 90 90): ") | color(C_DIM),
                input_patch_hex->Render() | borderLight |
                    size(WIDTH, EQUAL, 34),
                text(" [Enter] Apply  [Esc] Cancel ") | dim | hcenter) |
           size(WIDTH, EQUAL, 38) | borderDouble |
           bgcolor(Color::RGB(20, 10, 10)) | center;
  });

  auto help_modal = Renderer([&] {
    auto row = [&](const std::string &k, const std::string &d,
                   Color c = Color::White) {
      return hbox(text(" " + k + " ") | color(c) | bold |
                      size(WIDTH, EQUAL, 12),
                  text(d));
    };
    Elements h;
    h.push_back(text(" ⬡ HELP — IxeRam ") | bold | color(C_ACCENT) | hcenter);
    h.push_back(separatorDouble());
    h.push_back(row("F2", "First scan (all writable memory)", C_GREEN));
    h.push_back(row("F7", "Next scan (refine results)", C_ACCENT));
    h.push_back(row("F8", "Clear all results", C_RED));
    h.push_back(row("T", "Choose value type", C_ACCENT2));
    h.push_back(row("Y", "Choose scan mode", C_ACCENT2));
    h.push_back(row("W", "Write value to address", C_ORANGE));
    h.push_back(row("G", "Go to address (hex or decimal)", C_YELLOW));
    h.push_back(row("B", "Build call graph from selected address", C_GREEN));
    h.push_back(
        row("E", "Export Ghidra Python label script to /tmp/", C_ACCENT2));
    h.push_back(row(
        "Tab", "Switch:  // 0=Addresses  1=Map  2=CG  3=Watch  4=Ptr", C_CYAN));
    h.push_back(row("F3", "Toggle Hex / Disassembler", C_CYAN));
    h.push_back(row("F4", "Attach PID", C_FG));
    h.push_back(row("F5", "Freeze / Unfreeze", C_CYAN));
    h.push_back(row("F6", "Filter suspicious-low", C_FG));
    h.push_back(row("Q", "Quit", C_RED));
    h.push_back(separatorLight());
    h.push_back(
        text(" GHIDRA: Copy Offset → Ghidra G (Go To) → imageBase+offset") |
        color(C_YELLOW));
    h.push_back(
        text(" E exports a Python script, run in Ghidra Script Manager") |
        color(C_DIM));
    h.push_back(text(" Thanks to developers: myster_gif") | color(C_CYAN));
    h.push_back(separatorDouble());
    h.push_back(text(" ESC to close ") | hcenter | color(C_DIM));
    return vbox(std::move(h)) | size(WIDTH, EQUAL, 66) | borderDouble |
           bgcolor(Color::RGB(10, 10, 18)) | center;
  });

  auto attach_modal = Renderer(input_pid, [&] {
    return vbox(text(" ◈ ATTACH PID ") | bold | color(C_ACCENT) | hcenter,
                separatorLight(),
                hbox(text(" PID: ") | color(C_DIM), input_pid->Render() | flex),
                separatorLight(),
                text(" [Enter]attach  [ESC]cancel ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 38) | borderDouble |
           bgcolor(Color::RGB(10, 10, 20)) | center;
  });

  auto scan_modal_r = Renderer(input_scan, [&] {
    return vbox(text(" ◈ FIRST SCAN ") | bold | color(C_GREEN) | hcenter,
                hbox(text(" Type: ") | color(C_DIM),
                     text(VALUE_TYPE_NAMES[selected_value_type_idx]) |
                         color(C_ACCENT2) | bold),
                hbox(text(" Val:  ") | color(C_DIM),
                     input_scan->Render() | flex),
                separatorLight(),
                text(" [T]type  [Enter]scan  [ESC]cancel ") | color(C_DIM) |
                    hcenter) |
           size(WIDTH, EQUAL, 50) | borderDouble |
           bgcolor(Color::RGB(10, 12, 18)) | center;
  });

  auto next_modal_r = Renderer(input_next, [&] {
    bool nv = (selected_scan_type_idx <= 3 || selected_scan_type_idx == 5 ||
               selected_scan_type_idx == 7);
    Elements e;
    e.push_back(text(" ◈ NEXT SCAN ") | bold | color(C_ACCENT) | hcenter);
    e.push_back(hbox(text(" Mode: ") | color(C_DIM),
                     text(SCAN_TYPE_NAMES[selected_scan_type_idx]) |
                         color(C_ACCENT2) | bold));
    e.push_back(
        hbox(text(" Type: ") | color(C_DIM),
             text(VALUE_TYPE_NAMES[selected_value_type_idx]) | color(C_CYAN)));
    e.push_back(separatorLight());
    if (nv)
      e.push_back(
          hbox(text(" Val:  ") | color(C_DIM), input_next->Render() | flex));
    else
      e.push_back(text(" (no value needed) ") | color(C_DIM));
    e.push_back(separatorLight());
    e.push_back(text(" [Y]mode  [Enter]scan  [ESC]cancel ") | color(C_DIM) |
                hcenter);
    return vbox(std::move(e)) | size(WIDTH, EQUAL, 52) | borderDouble |
           bgcolor(Color::RGB(10, 12, 18)) | center;
  });

  auto write_modal_r = Renderer(input_write, [&] {
    std::ostringstream sa;
    sa << "0x" << std::hex << std::uppercase << tracked_address;
    return vbox(text(" ◈ WRITE VALUE ") | bold | color(C_ORANGE) | hcenter,
                hbox(text(" Addr: ") | color(C_DIM),
                     text(sa.str()) | color(C_CYAN) | bold),
                hbox(text(" Type: ") | color(C_DIM),
                     text(VALUE_TYPE_NAMES[selected_value_type_idx]) |
                         color(C_ACCENT2)),
                hbox(text(" Curr: ") | color(C_DIM),
                     text(scanner.read_value_str(tracked_address)) |
                         color(C_GREEN) | bold),
                separatorLight(),
                hbox(text(" New:  ") | color(C_DIM),
                     input_write->Render() | flex),
                separatorLight(),
                text(" [Enter]write  [ESC]cancel ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 46) | borderDouble |
           bgcolor(Color::RGB(14, 10, 10)) | center;
  });

  auto goto_modal_r = Renderer(input_goto_a, [&] {
    return vbox(text(" ◈ GO TO ADDRESS ") | bold | color(C_YELLOW) | hcenter,
                separatorLight(),
                hbox(text(" Addr: ") | color(C_DIM),
                     input_goto_a->Render() | flex),
                separatorLight(),
                text(" hex (0x...) or decimal ") | color(C_DIM) | hcenter,
                text(" [Enter]jump  [ESC]cancel ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 48) | borderDouble |
           bgcolor(Color::RGB(14, 14, 10)) | center;
  });

  auto type_modal_r = Renderer([&] {
    Elements it;
    for (int i = 0; i < VALUE_TYPE_COUNT; ++i) {
      auto r =
          hbox(text("  " + std::string(VALUE_TYPE_NAMES[i]) + "  ") | bold,
               text("(" + std::to_string((int)valueTypeSize(VALUE_TYPES[i])) +
                    "B)") |
                   color(C_DIM));
      it.push_back(i == selected_value_type_idx
                       ? r | bgcolor(C_SEL_BG) | color(Color::White)
                       : r | color(C_FG));
    }
    return vbox(text(" ◈ VALUE TYPE ") | bold | color(C_ACCENT2) | hcenter,
                separatorLight(), vbox(std::move(it)), separatorLight(),
                text(" ↑/↓ [Enter]pick [ESC]close ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 30) | borderDouble |
           bgcolor(Color::RGB(10, 10, 18)) | center;
  });

  auto stype_modal_r = Renderer([&] {
    Elements it;
    for (int i = 0; i < SCAN_TYPE_COUNT; ++i) {
      auto r = text("  " + std::string(SCAN_TYPE_NAMES[i]) + "  ") | bold;
      it.push_back(i == selected_scan_type_idx
                       ? r | bgcolor(C_SEL_BG) | color(Color::White)
                       : r | color(C_FG));
    }
    return vbox(text(" ◈ SCAN MODE ") | bold | color(C_ACCENT2) | hcenter,
                separatorLight(), vbox(std::move(it)), separatorLight(),
                text(" ↑/↓ [Enter]pick [ESC]close ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 28) | borderDouble |
           bgcolor(Color::RGB(10, 10, 18)) | center;
  });

  auto ghidra_base_modal_r = Renderer(input_ghidra_base, [&] {
    return vbox(text(" ◈ SET GHIDRA IMAGE BASE ") | bold | color(C_ACCENT) |
                    hcenter,
                separatorLight(),
                hbox(text(" Base: ") | color(C_DIM),
                     input_ghidra_base->Render() | flex),
                separatorLight(),
                text(" current: 0x" + hex_str(ghidra_image_base)) |
                    color(C_DIM) | hcenter,
                text(" [Enter]set  [ESC]cancel ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 48) | borderDouble |
           bgcolor(Color::RGB(10, 10, 20)) | center;
  });

  auto watch_modal_r = Renderer(input_watch_desc, [&] {
    return vbox(text(" ◈ ADD TO WATCHLIST ") | bold | color(C_ACCENT) | hcenter,
                separatorLight(),
                hbox(text(" Addr: ") | color(C_DIM),
                     text(hex_str(tracked_address)) | color(C_CYAN)),
                hbox(text(" Desc: ") | color(C_DIM),
                     input_watch_desc->Render() | flex),
                separatorLight(),
                text(" [Enter]add  [ESC]cancel ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 46) | borderDouble |
           bgcolor(Color::RGB(10, 15, 20)) | center;
  });

  auto speedhack_modal_r = Renderer(input_speedhack, [&] {
    return vbox(text(" ◈ SPEEDHACK ") | bold | color(C_YELLOW) | hcenter,
                separatorLight(),
                hbox(text(" Speed: ") | color(C_DIM),
                     input_speedhack->Render() | flex),
                separatorLight(),
                text(" e.g. 0.5 (slow) or 2.0 (fast) ") | color(C_DIM) |
                    hcenter,
                text(" [Enter]apply  [ESC]cancel ") | color(C_DIM) | hcenter) |
           size(WIDTH, EQUAL, 40) | borderDouble |
           bgcolor(Color::RGB(20, 20, 10)) | center;
  });

  auto root = Renderer([&] {
    Element base = main_layout->Render();
    if (show_type_modal)
      base = dbox({base, type_modal_r->Render() | center});
    if (show_scan_type_modal)
      base = dbox({base, stype_modal_r->Render() | center});
    if (show_help_modal)
      base = dbox({base, help_modal->Render() | center});
    if (show_attach_modal)
      base = dbox({base, attach_modal->Render() | center});
    if (show_scan_modal)
      base = dbox({base, scan_modal_r->Render() | center});
    if (show_next_scan_modal)
      base = dbox({base, next_modal_r->Render() | center});
    if (show_write_modal)
      base = dbox({base, write_modal_r->Render() | center});
    if (show_goto_modal)
      base = dbox({base, goto_modal_r->Render() | center});
    if (show_ghidra_base_modal)
      base = dbox({base, ghidra_base_modal_r->Render() | center});
    if (show_watch_modal)
      base = dbox({base, watch_modal_r->Render() | center});
    if (show_patch_modal)
      base = dbox({base, patch_modal_r->Render() | center});
    if (show_speedhack_modal)
      base = dbox({base, speedhack_modal_r->Render() | center});
    return base;
  });

  // ──────────────────────────────────────────────────────────────────
  // EVENT HANDLER
  // ──────────────────────────────────────────────────────────────────
  auto component = CatchEvent(root, [&](Event ev) -> bool {
    if (show_type_modal) {
      if (ev == Event::Escape) {
        show_type_modal = false;
        return true;
      }
      if (ev == Event::ArrowDown) {
        if (selected_value_type_idx < VALUE_TYPE_COUNT - 1)
          selected_value_type_idx++;
        return true;
      }
      if (ev == Event::ArrowUp) {
        if (selected_value_type_idx > 0)
          selected_value_type_idx--;
        return true;
      }
      if (ev == Event::Return) {
        add_log("Type → " +
                std::string(VALUE_TYPE_NAMES[selected_value_type_idx]));
        show_type_modal = false;
        return true;
      }
      return true;
    }
    if (show_scan_type_modal) {
      if (ev == Event::Escape) {
        show_scan_type_modal = false;
        return true;
      }
      if (ev == Event::ArrowDown) {
        if (selected_scan_type_idx < SCAN_TYPE_COUNT - 1)
          selected_scan_type_idx++;
        return true;
      }
      if (ev == Event::ArrowUp) {
        if (selected_scan_type_idx > 0)
          selected_scan_type_idx--;
        return true;
      }
      if (ev == Event::Return) {
        add_log("Mode → " +
                std::string(SCAN_TYPE_NAMES[selected_scan_type_idx]));
        show_scan_type_modal = false;
        return true;
      }
      return true;
    }
    if (show_help_modal) {
      if (ev == Event::Escape || ev == Event::F1) {
        show_help_modal = false;
      }
      return true;
    }
    if (show_attach_modal) {
      if (ev == Event::Return) {
        do_attach();
        return true;
      }
      if (ev == Event::Escape) {
        show_attach_modal = false;
        return true;
      }
      return input_pid->OnEvent(ev);
    }
    if (show_scan_modal) {
      if (ev == Event::Return) {
        do_initial_scan();
        return true;
      }
      if (ev == Event::Escape) {
        show_scan_modal = false;
        return true;
      }
      if (ev == Event::Character('t') || ev == Event::Character('T')) {
        show_type_modal = true;
        return true;
      }
      return input_scan->OnEvent(ev);
    }
    if (show_next_scan_modal) {
      if (ev == Event::Return) {
        do_next_scan();
        return true;
      }
      if (ev == Event::Escape) {
        show_next_scan_modal = false;
        return true;
      }
      if (ev == Event::Character('y') || ev == Event::Character('Y')) {
        show_scan_type_modal = true;
        return true;
      }
      return input_next->OnEvent(ev);
    }
    if (show_write_modal) {
      if (ev == Event::Return) {
        do_write();
        return true;
      }
      if (ev == Event::Escape) {
        show_write_modal = false;
        write_value_input.clear();
        return true;
      }
      return input_write->OnEvent(ev);
    }
    if (show_goto_modal) {
      if (ev == Event::Return) {
        do_goto_action();
        return true;
      }
      if (ev == Event::Escape) {
        show_goto_modal = false;
        goto_addr_input.clear();
        return true;
      }
      return input_goto_a->OnEvent(ev);
    }
    if (show_ghidra_base_modal) {
      if (ev == Event::Return) {
        do_set_ghidra_base();
        return true;
      }
      if (ev == Event::Escape) {
        show_ghidra_base_modal = false;
        ghidra_base_input.clear();
        return true;
      }
      return input_ghidra_base->OnEvent(ev);
    }
    if (show_watch_modal) {
      if (ev == Event::Return) {
        do_add_watch();
        return true;
      }
      if (ev == Event::Escape) {
        show_watch_modal = false;
        return true;
      }
      return input_watch_desc->OnEvent(ev);
    }
    if (show_patch_modal) {
      if (ev == Event::Return) {
        if (!patch_hex_input.empty()) {
          std::vector<uint8_t> bytes;
          bool is_hex = true;
          std::stringstream ss(patch_hex_input);
          std::string bs;
          while (ss >> bs) {
            try {
              if (bs.find_first_not_of("0123456789abcdefABCDEF") !=
                  std::string::npos) {
                is_hex = false;
                break;
              }
              bytes.push_back((uint8_t)std::stoul(bs, nullptr, 16));
            } catch (...) {
              is_hex = false;
              break;
            }
          }

          if (!is_hex) {
            bytes.clear();
            ks_engine *ks;
            ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
            if (err == KS_ERR_OK) {
              unsigned char *encode;
              size_t size;
              size_t count;
              if (ks_asm(ks, patch_hex_input.c_str(), patch_addr, &encode,
                         &size, &count) == KS_ERR_OK) {
                for (size_t i = 0; i < size; i++)
                  bytes.push_back(encode[i]);
                ks_free(encode);
              } else {
                add_log("✗ Assembler error: " +
                        std::string(ks_strerror(ks_errno(ks))));
              }
              ks_close(ks);
            }
          }

          if (!bytes.empty()) {
            engine.write_memory(patch_addr, bytes.data(), bytes.size());
            add_log("✓ Patched " + std::to_string(bytes.size()) + " bytes at " +
                    hex_str(patch_addr));
          }
        }
        show_patch_modal = false;
        return true;
      }
      if (ev == Event::Escape) {
        show_patch_modal = false;
        return true;
      }
      return input_patch_hex->OnEvent(ev);
    }

    if (show_speedhack_modal) {
      if (ev == Event::Return) {
        try {
          double spd = std::stod(speedhack_input);
          std::string cmd =
              "mkdir -p /dev/shm && head -c 8 /dev/zero > /dev/shm/speedhack_" +
              std::to_string(engine.get_pid()); // Create if not exists
          system(cmd.c_str());
          FILE *f =
              fopen(("/dev/shm/speedhack_" + std::to_string(engine.get_pid()))
                        .c_str(),
                    "wb");
          if (f) {
            fwrite(&spd, sizeof(double), 1, f);
            fclose(f);
            add_log("✓ Speedhack set to " + speedhack_input +
                    "x (Ensure libspeedhack.so is preloaded via LD_PRELOAD)");
          } else {
            add_log("✗ Failed to write speedhack config");
          }
        } catch (...) {
          add_log("✗ Invalid speed");
        }
        show_speedhack_modal = false;
        return true;
      }
      if (ev == Event::Escape) {
        show_speedhack_modal = false;
        return true;
      }
      return input_speedhack->OnEvent(ev);
    }

    if (ev == Event::Character('q') || ev == Event::Character('Q')) {
      screen.ExitLoopClosure()();
      return true;
    }
    if (ev == Event::F1) {
      show_help_modal = true;
      return true;
    }
    if (ev == Event::F2) {
      scan_value.clear();
      show_scan_modal = true;
      return true;
    }
    if (ev == Event::F3) {
      show_disasm = !show_disasm;
      add_log(show_disasm ? "→Disasm" : "→Hex");
      return true;
    }
    if (ev == Event::F4) {
      pid_input.clear();
      show_attach_modal = true;
      return true;
    }
    if (ev == Event::F5) {
      if (tracked_address) {
        if (frozen_addresses.count(tracked_address)) {
          frozen_addresses.erase(tracked_address);
          add_log("✓ Unfrozen " + hex_str(tracked_address));
        } else {
          size_t sz = valueTypeSize(scanner.get_value_type());
          FrozenEntry fe;
          fe.bytes.resize(sz, 0);
          engine.read_memory(tracked_address, fe.bytes.data(), sz);
          fe.display_val = scanner.read_value_str(tracked_address);
          frozen_addresses[tracked_address] = fe;
          add_log("❄ Frozen " + hex_str(tracked_address) + " = " +
                  fe.display_val);
        }
      }
      return true;
    }
    if (ev == Event::F6) {
      hide_suspicious_low = !hide_suspicious_low;
      add_log(hide_suspicious_low ? "Filter:suspicious" : "Filter:all");
      return true;
    }
    if (ev == Event::F7) {
      next_scan_value.clear();
      show_next_scan_modal = true;
      return true;
    }
    if (ev == Event::F8) {
      scanner.clear_results();
      categorized_results.clear();
      value_history.clear();
      last_vals_for_color.clear();
      frozen_addresses.clear();
      selected_result_idx = 0;
      tracked_address = 0;
      add_log("✓ Cleared");
      return true;
    }
    if (ev == Event::F9) {
      ghidra_base_input = hex_str(ghidra_image_base);
      show_ghidra_base_modal = true;
      return true;
    }
    if (ev == Event::F10) {
      show_speedhack_modal = true;
      return true;
    }
    if (ev == Event::Character('w') || ev == Event::Character('W')) {
      if (tracked_address) {
        write_value_input.clear();
        show_write_modal = true;
      } else
        add_log("✗ No address");
      return true;
    }
    if (ev == Event::Character('g') || ev == Event::Character('G')) {
      goto_addr_input.clear();
      show_goto_modal = true;
      return true;
    }
    if (ev == Event::Character('t') || ev == Event::Character('T')) {
      show_type_modal = true;
      return true;
    }
    if (ev == Event::Character('y') || ev == Event::Character('Y')) {
      show_scan_type_modal = true;
      return true;
    }
    if (ev == Event::Character('b') || ev == Event::Character('B')) {
      if (tracked_address) {
        add_log("Building CG from " + hex_str(tracked_address) + "...");
        update_memory_map();
        build_call_graph(tracked_address, cg_max_depth);
        add_log("✓ CG: " + std::to_string(call_graph.size()) + " nodes");
        main_tab = 2;
      } else
        add_log("✗ No address");
      return true;
    }
    if (ev == Event::Character('e') || ev == Event::Character('E')) {
      std::string path =
          "/tmp/ghidra_" + std::to_string(engine.get_pid()) + ".py";
      export_ghidra_script(path);
      return true;
    }
    if (ev == Event::Character('a') || ev == Event::Character('A')) {
      if (tracked_address) {
        watch_desc_input.clear();
        show_watch_modal = true;
      }
      return true;
    }
    if (ev == Event::Character('p') || ev == Event::Character('P')) {
      do_ptr_scan();
      return true;
    }
    if (ev == Event::Tab || ev == Event::Character('\t')) {
      main_tab = (main_tab + 1) % 7;
      return true;
    }

    // Disassembler specific keys
    if (main_tab == 5 && !disasm_lines.empty()) {
      if (ev == Event::Character(' ')) {
        patch_addr = disasm_lines[selected_disasm_idx].addr;
        patch_hex_input.clear();
        show_patch_modal = true;
        return true;
      }
      if (ev == Event::Return) {
        auto ops = disasm_lines[selected_disasm_idx].ops;
        if (ops.find("0x") == 0) {
          try {
            uintptr_t target = std::stoull(ops, nullptr, 16);
            disasm_history.push_back(tracked_address);
            tracked_address = target;
            selected_disasm_idx = 0;
            add_log("Followed jump to " + hex_str(target));
          } catch (...) {
          }
        }
        return true;
      }
      if (ev == Event::Backspace) {
        if (!disasm_history.empty()) {
          tracked_address = disasm_history.back();
          disasm_history.pop_back();
          selected_disasm_idx = 0;
          add_log("Returned to " + hex_str(tracked_address));
        }
        return true;
      }
    }

    if (ev == Event::ArrowDown) {
      if (main_tab == 0) {
        if (selected_result_idx < (int)categorized_results.size() - 1)
          selected_result_idx++;
      } else if (main_tab == 1) {
        if (selected_map_idx < (int)map_entries.size() - 1)
          selected_map_idx++;
      } else if (main_tab == 2) {
        if (selected_cg_idx < (int)call_graph.size() - 1)
          selected_cg_idx++;
      } else if (main_tab == 3) {
        if (selected_watch_idx < (int)watchlist.size() - 1)
          selected_watch_idx++;
      } else if (main_tab == 4) {
        if (selected_ptr_idx < (int)ptr_results.size() - 1)
          selected_ptr_idx++;
      } else if (main_tab == 5) {
        if (selected_disasm_idx < (int)disasm_lines.size() - 1)
          selected_disasm_idx++;
      }
      return true;
    }
    if (ev == Event::ArrowUp) {
      if (main_tab == 0) {
        if (selected_result_idx > 0)
          selected_result_idx--;
      } else if (main_tab == 1) {
        if (selected_map_idx > 0)
          selected_map_idx--;
      } else if (main_tab == 2) {
        if (selected_cg_idx > 0)
          selected_cg_idx--;
      } else if (main_tab == 3) {
        if (selected_watch_idx > 0)
          selected_watch_idx--;
      } else if (main_tab == 4) {
        if (selected_ptr_idx > 0)
          selected_ptr_idx--;
      } else if (main_tab == 5) {
        if (selected_disasm_idx > 0)
          selected_disasm_idx--;
        else if (selected_disasm_idx == 0 && tracked_address > 0) {
          tracked_address -= 1; // Slide window slightly back
        }
      }
      return true;
    }
    return false;
  });

  std::thread fz(&TUI::freezing_loop, this);
  fz.detach();
  std::thread upd([&] {
    while (true) {
      update_tracking_data();
      if (main_tab == 1)
        update_memory_map();
      screen.PostEvent(Event::Custom);
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
  });
  upd.detach();

  KittyGraphics::render_logo_placeholder();
  screen.Loop(component);
}
