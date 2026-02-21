#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

/**
 * Utility to output images using Kitty Graphics Protocol
 * Protocol: \033_Gf=32,s=<w>,v=<h>,a=T;<base64_data>\033\\
 */
class KittyGraphics {
public:
  // Simple 8x8 checkerboard RGBA pattern as a "logo"
  static void render_logo_placeholder() {
    if (!is_kitty_supported()) {
      render_ascii_fallback();
      return;
    }

    // 8x8 RGBA (32bit) = 64 pixels * 4 bytes = 256 bytes
    std::vector<uint8_t> rgba_data;
    for (int y = 0; y < 8; ++y) {
      for (int x = 0; x < 8; ++x) {
        bool is_blue = (x + y) % 2 == 0;
        rgba_data.push_back(is_blue ? 122 : 30); // R
        rgba_data.push_back(is_blue ? 162 : 30); // G
        rgba_data.push_back(is_blue ? 247 : 50); // B
        rgba_data.push_back(255);                // A
      }
    }

    std::string b64 = base64_encode(rgba_data);
    std::cout << "\033_Gf=32,s=8,v=8,a=T,q=2;" << b64 << "\033\\" << std::flush;
  }

  static bool is_kitty_supported() {
    const char *term = std::getenv("TERM");
    const char *kitty_id = std::getenv("KITTY_WINDOW_ID");
    return (term && std::string(term).find("kitty") != std::string::npos) ||
           kitty_id != nullptr;
  }

  static void render_ascii_fallback() {
    // Professional block art logo
    std::cout << "  ▄▄▄▄▄▄▄  \n"
              << "  █ ▄▄▄ █  \n"
              << "  █ █▀█ █  \n"
              << "  █ ▀▀▀ █  \n"
              << "  ▀▀▀▀▀▀▀  " << std::endl;
  }

private:
  static std::string base64_encode(const std::vector<uint8_t> &data) {
    static const char lookup[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
      val = (val << 8) + c;
      valb += 8;
      while (valb >= 0) {
        out.push_back(lookup[(val >> valb) & 0x3F]);
        valb -= 6;
      }
    }
    if (valb > -6)
      out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
      out.push_back('=');
    return out;
  }
};
