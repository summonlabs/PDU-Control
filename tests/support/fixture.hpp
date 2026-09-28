#pragma once

// Deterministic test fixtures: a complete, valid scenario applied through the
// public API, and a scratch directory that refuses to touch anything outside
// the directory it created.

#include <cstdint>
#include <string>

#include "pdu_control/engine.hpp"
#include "pdu_control/status.hpp"

namespace pdu_test {

// The fixture describes library values by their library names, so that a reader
// of a test sees the same type names the library uses.
using namespace ::pdu_control;  // NOLINT(google-build-using-namespace)

/// One PDU with one branch, a satisfied protected interlock, a control grant,
/// and a fresh observation reading de_energized.
struct Scenario {
  PduId pdu;
  PduGeneration pdu_generation;
  BranchId branch;
  BranchGeneration branch_generation;
  InterlockId interlock;
  AuthorityId grant;
  IssuerId issuer;
  AuthorityEpoch epoch;
  SourceId source;
  Current continuous_limit;
  LogicalTick start_tick;
};

Scenario make_scenario(const std::string& suffix, std::uint64_t start_tick = 1);

EngineOptions base_options();

/// Applies the scenario to an engine: adopts the epoch, registers the PDU and
/// the branch, declares and satisfies the interlock, records the grant, and
/// records one fresh observation reading de_energized.
Status apply_scenario(PduControlEngine& engine, const Scenario& scenario,
                      LifecycleState lifecycle = LifecycleState::active);

/// Builds an observation for the scenario's branch.
TelemetryObservation make_observation(const Scenario& scenario, LogicalTick tick,
                                      std::uint64_t sequence, BranchCondition condition,
                                      EvidenceQuality quality = EvidenceQuality::good);

/// A scratch directory under the test binary directory.
class TempDir {
 public:
  explicit TempDir(const std::string& name);
  ~TempDir();
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  /// A path of one file inside this directory. Refuses separator characters and
  /// traversal, so a test cannot escape its own scratch directory.
  [[nodiscard]] Status file(const std::string& leaf, std::string& out) const;
  [[nodiscard]] std::string store_path() const;

 private:
  std::string path_;
};

}  // namespace pdu_test
