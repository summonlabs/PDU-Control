#include "cli_json.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace pdu_cli {

std::string json_escape(std::string_view text) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size() + 2);
  for (const char value : text) {
    const auto code = static_cast<unsigned char>(value);
    switch (value) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (code < 0x20) {
          out.append("\\u00");
          out.push_back(kDigits[(code >> 4) & 0xF]);
          out.push_back(kDigits[code & 0xF]);
        } else {
          out.push_back(value);
        }
        break;
    }
  }
  return out;
}

void JsonObject::add(std::string key, std::string value) {
  entries_.emplace_back(std::move(key), "\"" + json_escape(value) + "\"");
}

void JsonObject::add(std::string key, std::uint64_t value) {
  entries_.emplace_back(std::move(key), std::to_string(value));
}

void JsonObject::add(std::string key, std::int64_t value) {
  entries_.emplace_back(std::move(key), std::to_string(value));
}

void JsonObject::add(std::string key, bool value) {
  entries_.emplace_back(std::move(key), value ? "true" : "false");
}

void JsonObject::add_null(std::string key) {
  entries_.emplace_back(std::move(key), "null");
}

std::string JsonObject::str() const {
  std::string out = "{";
  bool first = true;
  for (const auto& entry : entries_) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out.push_back('"');
    out.append(json_escape(entry.first));
    out.append("\":");
    out.append(entry.second);
  }
  out.push_back('}');
  return out;
}

}  // namespace pdu_cli
