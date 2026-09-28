#pragma once

// A deterministic JSON writer.
//
// Objects preserve insertion order because the writer stores key/value pairs in
// a vector: nothing in this tool iterates an unordered container when producing
// output, so two runs over the same state print the same bytes.

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pdu_cli {

/// Escapes a string for inclusion in a JSON document.
[[nodiscard]] std::string json_escape(std::string_view text);

/// An ordered JSON object.
class JsonObject {
 public:
  void add(std::string key, std::string value);
  void add(std::string key, std::uint64_t value);
  void add(std::string key, std::int64_t value);
  void add(std::string key, bool value);
  void add_null(std::string key);
  [[nodiscard]] std::string str() const;
  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

 private:
  std::vector<std::pair<std::string, std::string>> entries_;
};

}  // namespace pdu_cli
