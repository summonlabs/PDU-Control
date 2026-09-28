// pdu-control: the inspection and administration tool.
//
// The tool is a thin shell over the library. It opens a store, performs exactly
// one verb, prints what the library reported, and closes. It never reimplements
// validation, never invents a decision, and never prints a success line for a
// refusal.
//
// Control verbs drive a deterministic synthetic adapter. Everything that came
// from it is labeled SYNTHETIC: this tool drives no hardware, and no output of
// this tool is hardware evidence.

#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "cli_json.hpp"
#include "pdu_control/engine.hpp"
#include "pdu_control/synthetic_adapter.hpp"
#include "pdu_control/version.hpp"

using namespace pdu_control;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitRefused = 1;
constexpr int kExitUsage = 2;
constexpr std::size_t kDefaultListLimit = 100;
constexpr std::size_t kMaxListLimit = 10000;

struct Args {
  std::string store;
  std::string verb;
  std::string action;
  std::vector<std::pair<std::string, std::string>> options;
  bool json{false};
  bool quiet{false};
  bool help{false};
  bool version{false};
  bool verify{false};
  bool read_back{false};

  [[nodiscard]] bool has(const std::string& key) const {
    for (const auto& entry : options) {
      if (entry.first == key) {
        return true;
      }
    }
    return false;
  }
  [[nodiscard]] std::string get(const std::string& key,
                                const std::string& fallback = std::string()) const {
    for (const auto& entry : options) {
      if (entry.first == key) {
        return entry.second;
      }
    }
    return fallback;
  }
  [[nodiscard]] std::vector<std::string> get_all(const std::string& key) const {
    std::vector<std::string> values;
    for (const auto& entry : options) {
      if (entry.first == key) {
        values.push_back(entry.second);
      }
    }
    return values;
  }
};

const char* kUsage =
    "usage: pdu-control <verb> [options]\n"
    "  init --pdu ID --generation N [--lifecycle S] [--label L]\n"
    "  inspect [--pdu ID] [--branch ID]\n"
    "  branch add --pdu P --branch B --generation N [--lifecycle S] [--label L]\n"
    "             [--continuous-mA N] [--peak-mA N] [--power-mW N]\n"
    "             [--limit-issuer I --limit-authority A --limit-epoch E] [--interlock ID]...\n"
    "  branch show --pdu P --branch B\n"
    "  branch limits --pdu P --branch B --generation N --revision R --epoch E\n"
    "                --limit-issuer I --limit-authority A --limit-epoch E [--continuous-mA N]\n"
    "  branch enable|disable --pdu P --branch B --epoch E --pdu-generation N\n"
    "                        --branch-generation N [--revision R] [--key K] [--projected-mA N]\n"
    "                        [--tick T] [--adapter-mode MODE] [--verify]\n"
    "  lifecycle set --pdu P [--branch B] --to S --epoch E --pdu-generation N\n"
    "                --branch-generation N --revision R [--tick T] [--actor A]\n"
    "  evaluate --pdu P --branch B --intent energize|de_energize --epoch E\n"
    "           --pdu-generation N --branch-generation N [--revision R] [--projected-mA N]\n"
    "           [--key K] [--tick T] [--actor A]\n"
    "  issue --pdu P --branch B --intent ... --epoch E --pdu-generation N\n"
    "        --branch-generation N --key K [--tick T] [--adapter-mode MODE] [--verify]\n"
    "  attempts [--limit N] [--attempt N] [--key K]\n"
    "  verify --attempt N [--adapter-mode MODE] [--read-back]\n"
    "  revalidate --pdu P --branch B --pdu-generation N --branch-generation N\n"
    "             --source S --sequence N --tick T --condition C [--quality Q]\n"
    "  history [--limit N] [--pdu P] [--branch B] [--attempt N] [--kind K]\n"
    "  store-audit\n"
    "  epoch adopt --epoch E\n"
    "  tick advance --tick T\n"
    "  grant add --grant ID --issuer I --epoch E --pdu P --branch B --pdu-generation N\n"
    "            --branch-generation N --actions A[,B] --issued T [--not-after T]\n"
    "  grant revoke --grant ID --epoch E --tick T\n"
    "  override add --override ID --issuer I --epoch E --pdu P --branch B --pdu-generation N\n"
    "               --branch-generation N --issued T --not-after T\n"
    "  interlock declare --interlock ID --pdu P --branch B [--class protected|advisory]\n"
    "                    --epoch E --tick T\n"
    "  interlock report --interlock ID --state satisfied|open|unknown --epoch E --tick T\n"
    "                   [--clearance ID]\n"
    "  observe --pdu P --branch B --pdu-generation N --branch-generation N --source S\n"
    "          --sequence N --tick T --condition C [--quality Q] [--current-mA N]\n"
    "  resolve --attempt N --resolution cancelled|superseded --actor A --epoch E --tick T\n"
    "global: --store PATH (omit for an in-memory engine), --json, --quiet, --help, --version\n";

class Output {
 public:
  Output(bool json, bool quiet) : json_(json), quiet_(quiet) {}

  void field(const std::string& key, const std::string& value) {
    if (json_) {
      object_.add(key, value);
    } else if (!quiet_) {
      std::cout << key << "=" << value << "\n";
    }
  }
  void field(const std::string& key, std::uint64_t value) {
    if (json_) {
      object_.add(key, value);
    } else if (!quiet_) {
      std::cout << key << "=" << value << "\n";
    }
  }
  void field(const std::string& key, std::int64_t value) {
    if (json_) {
      object_.add(key, value);
    } else if (!quiet_) {
      std::cout << key << "=" << value << "\n";
    }
  }
  void field(const std::string& key, bool value) {
    if (json_) {
      object_.add(key, value);
    } else if (!quiet_) {
      std::cout << key << "=" << (value ? "true" : "false") << "\n";
    }
  }
  void note(const std::string& text) {
    if (!json_ && !quiet_) {
      std::cout << text << "\n";
    }
  }
  void finish() {
    if (json_) {
      std::cout << object_.str() << "\n";
    }
  }

 private:
  bool json_{false};
  bool quiet_{false};
  pdu_cli::JsonObject object_;
};

int refuse(const Status& status, const Args& args) {
  if (args.json) {
    pdu_cli::JsonObject object;
    object.add("ok", false);
    object.add("code", std::string(status.token()));
    object.add("detail", status.message());
    std::cout << object.str() << "\n";
  } else {
    std::cout << "error: " << status.token() << ": " << status.message() << "\n";
  }
  return kExitRefused;
}

int usage_error(const std::string& message) {
  std::cout << "usage: " << message << "\n";
  return kExitUsage;
}

/// Reports a failure that came from the command line itself as a usage error,
/// and anything else as a refusal. The distinction matters to a caller: exit 2
/// means "ask again with a well-formed command", exit 1 means "the request was
/// understood and refused".
int report_option_failure(const Status& status, const Args& args) {
  if (status.code() == StatusCode::invalid_argument ||
      status.code() == StatusCode::malformed_input || status.code() == StatusCode::overflow ||
      status.code() == StatusCode::out_of_range) {
    return usage_error(status.message());
  }
  return refuse(status, args);
}

Result<std::uint64_t> parse_u64(const std::string& text) {
  if (text.empty()) {
    return Status::failure(StatusCode::invalid_argument, "an empty number was given");
  }
  std::uint64_t value = 0;
  for (const char digit : text) {
    if (digit < '0' || digit > '9') {
      return Status::failure(StatusCode::malformed_input,
                             "the value '" + text + "' is not a non-negative integer");
    }
    const std::uint64_t next = value * 10 + static_cast<std::uint64_t>(digit - '0');
    if (next < value) {
      return Status::failure(StatusCode::overflow,
                             "the value '" + text + "' overflows a 64-bit count");
    }
    value = next;
  }
  return value;
}

Result<std::string> require(const Args& args, const std::string& key) {
  const std::string value = args.get(key);
  if (value.empty()) {
    return Status::failure(StatusCode::invalid_argument, "--" + key + " is required");
  }
  return value;
}

Result<std::uint64_t> number(const Args& args, const std::string& key, std::uint64_t fallback,
                             bool required) {
  const std::string text = args.get(key);
  if (text.empty()) {
    if (required) {
      return Status::failure(StatusCode::invalid_argument, "--" + key + " is required");
    }
    return fallback;
  }
  return parse_u64(text);
}

template <typename Tag>
Result<Counter<Tag>> counter(const Args& args, const std::string& key, bool required = true) {
  const auto value = number(args, key, 0, required);
  if (!value.ok()) {
    return value.status();
  }
  return Counter<Tag>::from(value.value());
}

template <typename Tag>
Result<Identifier<Tag>> identifier(const Args& args, const std::string& key) {
  const auto text = require(args, key);
  if (!text.ok()) {
    return text.status();
  }
  return Identifier<Tag>::parse(text.value());
}

Result<PduId> pdu_id(const Args& args) { return identifier<PduIdTag>(args, "pdu"); }
Result<BranchId> branch_id(const Args& args) { return identifier<BranchIdTag>(args, "branch"); }

EngineOptions cli_options() {
  EngineOptions options;
  options.evidence.max_age_ticks = LogicalTick::from(1000000);
  options.idempotency_window = 64;
  options.audit_capacity = 1024;
  return options;
}

Result<PduControlEngine> open_engine(const Args& args) {
  if (args.store.empty()) {
    return PduControlEngine::in_memory(cli_options());
  }
  return PduControlEngine::open(args.store, OpenMode::open_or_create, cli_options());
}

SyntheticMode adapter_mode(const Args& args) {
  SyntheticMode mode = SyntheticMode::honor;
  if (args.has("adapter-mode")) {
    (void)parse_synthetic_mode(args.get("adapter-mode"), mode);
  }
  return mode;
}

Result<SyntheticPduAdapter> make_adapter(const Args& args, const PduControlEngine& engine,
                                         const PduId& pdu, const BranchId& branch) {
  if (args.has("adapter-mode")) {
    SyntheticMode unused = SyntheticMode::honor;
    if (!parse_synthetic_mode(args.get("adapter-mode"), unused)) {
      return Status::failure(StatusCode::invalid_argument,
                             "unrecognized --adapter-mode '" + args.get("adapter-mode") + "'");
    }
  }
  const auto snapshot = engine.inspect_branch(pdu, branch);
  if (!snapshot.ok()) {
    return snapshot.status();
  }
  SyntheticPduAdapter::Config config;
  config.id = AdapterId::parse("synthetic-cli").value();
  config.vendor = IssuerId::parse("synthetic").value();
  config.model = "synthetic-cli";
  config.firmware = "0";
  config.pdu = pdu;
  config.branch = branch;
  config.pdu_generation = snapshot.value().pdu_generation;
  config.branch_generation = snapshot.value().generation;
  config.mode = adapter_mode(args);
  // The simulated physical state continues from what the store last verified, so
  // a walkthrough across separate invocations stays coherent. That is a
  // simulator convenience: what it reports is still only evidence, and it is
  // still labeled SYNTHETIC.
  config.initial_condition = snapshot.value().verified.established()
                                 ? snapshot.value().verified.condition.value()
                                 : BranchCondition::de_energized;
  config.reading_taken_at = Instant::logical(engine.current_tick());
  config.reading_tick_step = LogicalTick::from(1);
  // A read-back measures now, so the reading is reported at the instant the
  // caller asked for it.
  config.read_at_request_instant = true;
  return SyntheticPduAdapter(config);
}

void report_branch(Output& out, const BranchSnapshot& branch) {
  out.field("pdu", branch.pdu.value());
  out.field("branch", branch.id.value());
  out.field("pdu-generation", branch.pdu_generation.value());
  out.field("branch-generation", branch.generation.value());
  out.field("revision", branch.revision.value());
  out.field("lifecycle", std::string(to_token(branch.lifecycle)));
  out.field("pdu-lifecycle", std::string(to_token(branch.pdu_lifecycle)));
  out.field("control-scope", std::string(to_token(branch.control_scope)));
  out.field("commanded-state", std::string(to_token(branch.commanded.condition.state())));
  if (branch.commanded.condition.has_value()) {
    out.field("commanded", std::string(to_token(branch.commanded.condition.value())));
  }
  out.field("commanded-by-attempt", branch.commanded.by_attempt.value());
  out.field("verified-state", std::string(to_token(branch.verified.condition.state())));
  if (branch.verified.condition.has_value()) {
    out.field("verified", std::string(to_token(branch.verified.condition.value())));
  }
  out.field("verified-by-observation", branch.verified.observation.value());
  out.field("observed-present", branch.observation.present);
  if (branch.observation.present) {
    out.field("observed", std::string(to_token(branch.observation.condition)));
    out.field("observed-quality", std::string(to_token(branch.observation.quality)));
    out.field("observed-freshness", std::string(to_token(branch.observation.freshness)));
    out.field("observed-source", branch.observation.source.value());
    out.field("observed-sequence", branch.observation.sequence.value());
    out.field("observed-age-ticks-known", branch.observation.age_known);
    if (branch.observation.age_known) {
      out.field("observed-age-ticks", branch.observation.age_ticks.value());
    }
  }
  out.field("continuous-limit-state",
            std::string(to_token(branch.limits.continuous_current.state())));
  if (branch.limits.continuous_current.has_value()) {
    out.field("continuous-limit-mA", branch.limits.continuous_current.value().raw());
  }
  out.field("limit-provenance-issuer", branch.limits.provenance.issuer.value());
  out.field("limit-provenance-authority", branch.limits.provenance.authority.value());
  out.field("limit-provenance-epoch", branch.limits.provenance.epoch.value());
  out.field("interlock-verdict", std::string(to_token(branch.interlocks_summary.verdict)));
  out.field("interlock-protected",
            static_cast<std::uint64_t>(branch.interlocks_summary.protected_count));
  out.field("interlock-satisfied",
            static_cast<std::uint64_t>(branch.interlocks_summary.satisfied_count));
  if (branch.interlocks_summary.has_deciding) {
    out.field("interlock-deciding", branch.interlocks_summary.deciding.value());
  }
  out.field("permission-verdict", std::string(to_token(branch.permission.verdict)));
  out.field("last-attempt", branch.last_attempt.value());
  out.field("unresolved-attempt", branch.unresolved_attempt);
}

void report_attempt(Output& out, const AttemptRecord& attempt) {
  out.field("attempt", attempt.id.value());
  out.field("key", attempt.key.value());
  out.field("pdu", attempt.pdu.value());
  out.field("branch", attempt.branch.value());
  out.field("intent", std::string(to_token(attempt.intent)));
  out.field("outcome", std::string(to_token(attempt.outcome)));
  out.field("code", std::string(to_token(attempt.code)));
  out.field("effect", std::string(to_token(attempt.effect)));
  out.field("dispatched", attempt.dispatched);
  out.field("applied-command", attempt.applied_command);
  out.field("replayed", attempt.replayed);
  out.field("maintenance-override", attempt.maintenance_override_used);
  out.field("adapter-sequence", attempt.adapter_sequence.value());
  out.field("adapter-disposition", std::string(to_token(attempt.disposition)));
  out.field("validated-preconditions",
            static_cast<std::uint64_t>(attempt.authorization.validated()));
  out.field("complete-preconditions", attempt.authorization.complete_for_control());
  out.field("verifying-observation", attempt.verifying_observation.value());
  out.field("issued-at", attempt.issued_at.value());
  out.field("verified-at", attempt.verified_at.value());
  if (!attempt.detail.empty()) {
    out.field("detail", attempt.detail);
  }
}

void report_decision(Output& out, const Decision& decision) {
  out.field("eligible", decision.eligible);
  out.field("code", std::string(to_token(decision.code)));
  out.field("detail", decision.detail);
  out.field("permission", std::string(to_token(decision.permission)));
  out.field("override", std::string(to_token(decision.override_verdict)));
  out.field("interlock", std::string(to_token(decision.interlocks.verdict)));
  out.field("limit", std::string(to_token(decision.limit)));
  out.field("replay", decision.replay);
  out.field("maintenance-override-used", decision.maintenance_override_used);
  std::uint64_t index = 0;
  for (const PreconditionCheck& check : decision.trace) {
    const std::string prefix = "trace-" + std::to_string(index);
    out.field(prefix + "-precondition", std::string(to_token(check.kind)));
    out.field(prefix + "-satisfied", check.satisfied);
    out.field(prefix + "-code", std::string(to_token(check.code)));
    ++index;
  }
}

Result<BranchControlRequest> control_request(const Args& args) {
  BranchControlRequest request;
  const auto pdu = pdu_id(args);
  if (!pdu.ok()) {
    return pdu.status();
  }
  const auto branch = branch_id(args);
  if (!branch.ok()) {
    return branch.status();
  }
  const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
  if (!epoch.ok()) {
    return epoch.status();
  }
  const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation");
  if (!pdu_generation.ok()) {
    return pdu_generation.status();
  }
  const auto branch_generation = counter<BranchGenerationTag>(args, "branch-generation");
  if (!branch_generation.ok()) {
    return branch_generation.status();
  }
  request.pdu = pdu.value();
  request.branch = branch.value();
  request.epoch = epoch.value();
  request.pdu_generation = pdu_generation.value();
  request.branch_generation = branch_generation.value();
  const auto revision = counter<StateRevisionTag>(args, "revision", false);
  if (!revision.ok()) {
    return revision.status();
  }
  request.planned_revision = revision.value();
  const std::string intent = args.get("intent", "energize");
  if (!parse_command_intent(intent, request.intent)) {
    return Status::failure(StatusCode::invalid_argument, "unrecognized --intent '" + intent + "'");
  }
  const auto actor = ActorId::parse(args.get("actor", "cli"));
  if (!actor.ok()) {
    return actor.status();
  }
  request.actor = actor.value();
  const std::string key_text = args.get("key", pdu.value().value() + "-" + branch.value().value() +
                                              "-" + intent);
  const auto key = IdempotencyKey::parse(key_text);
  if (!key.ok()) {
    return key.status();
  }
  request.key = key.value();
  request.requested_at = LogicalTick::from(number(args, "tick", 1, false).value_or(1));
  if (args.has("projected-mA")) {
    const auto raw = parse_u64(args.get("projected-mA"));
    if (!raw.ok()) {
      return raw.status();
    }
    if (raw.value() > 0x7FFFFFFFFFFFFFFFULL) {
      return Status::failure(StatusCode::overflow, "--projected-mA is too large");
    }
    request.projected_current =
        CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
  }
  return request;
}

Status settle_tick(PduControlEngine& engine, const Args& args) {
  const auto tick = number(args, "tick", 0, false);
  if (!tick.ok()) {
    return tick.status();
  }
  if (tick.value() == 0) {
    return Status::success();
  }
  if (engine.current_tick() >= LogicalTick::from(tick.value())) {
    return Status::success();
  }
  return engine.advance_tick(LogicalTick::from(tick.value()));
}

// --- verbs -----------------------------------------------------------------

int verb_init(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  const auto id = pdu_id(args);
  if (!id.ok()) {
    return refuse(id.status(), args);
  }
  const auto generation = counter<PduGenerationTag>(args, "generation");
  if (!generation.ok()) {
    return refuse(generation.status(), args);
  }
  PduDefinition definition;
  definition.id = id.value();
  definition.generation = generation.value();
  definition.label = args.get("label");
  definition.registered_at = LogicalTick::from(number(args, "tick", 1, false).value_or(1));
  if (args.has("lifecycle") && !parse_lifecycle_state(args.get("lifecycle"), definition.lifecycle)) {
    return usage_error("unrecognized --lifecycle");
  }
  const Status status = engine.register_pdu(definition);
  if (!status.ok()) {
    return refuse(status, args);
  }
  Output out(args.json, args.quiet);
  out.field("pdu", definition.id.value());
  out.field("generation", definition.generation.value());
  out.field("lifecycle", std::string(to_token(definition.lifecycle)));
  out.finish();
  return kExitOk;
}

int verb_inspect(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  Output out(args.json, args.quiet);

  if (args.has("pdu") && args.has("branch")) {
    const auto pdu = pdu_id(args);
    const auto branch = branch_id(args);
    if (!pdu.ok() || !branch.ok()) {
      return usage_error("--pdu and --branch must be valid identities");
    }
    const auto snapshot = engine.inspect_branch(pdu.value(), branch.value());
    if (!snapshot.ok()) {
      return refuse(snapshot.status(), args);
    }
    report_branch(out, snapshot.value());
  } else if (args.has("branch")) {
    const auto branch = branch_id(args);
    if (!branch.ok()) {
      return refuse(branch.status(), args);
    }
    const auto snapshot = engine.inspect_branch(branch.value());
    if (!snapshot.ok()) {
      return refuse(snapshot.status(), args);
    }
    report_branch(out, snapshot.value());
  } else {
    std::vector<PduSnapshot> pdus;
    if (args.has("pdu")) {
      const auto pdu = pdu_id(args);
      if (!pdu.ok()) {
        return refuse(pdu.status(), args);
      }
      const auto one = engine.inspect_pdu(pdu.value());
      if (!one.ok()) {
        return refuse(one.status(), args);
      }
      pdus.push_back(one.value());
    } else {
      pdus = engine.inspect_all();
    }
    std::uint64_t pdu_index = 0;
    for (const PduSnapshot& pdu : pdus) {
      const std::string prefix = "pdu-" + std::to_string(pdu_index) + "-";
      out.field(prefix + "id", pdu.id.value());
      out.field(prefix + "generation", pdu.generation.value());
      out.field(prefix + "revision", pdu.revision.value());
      out.field(prefix + "lifecycle", std::string(to_token(pdu.lifecycle)));
      out.field(prefix + "branches", static_cast<std::uint64_t>(pdu.branches.size()));
      for (const BranchSnapshot& branch : pdu.branches) {
        const std::string branch_prefix = "branch-" + branch.id.value() + "-";
        out.field(branch_prefix + "generation", branch.generation.value());
        out.field(branch_prefix + "revision", branch.revision.value());
        out.field(branch_prefix + "lifecycle", std::string(to_token(branch.lifecycle)));
        out.field(branch_prefix + "control-scope", std::string(to_token(branch.control_scope)));
        out.field(branch_prefix + "commanded-state",
                  std::string(to_token(branch.commanded.condition.state())));
        out.field(branch_prefix + "verified-state",
                  std::string(to_token(branch.verified.condition.state())));
        out.field(branch_prefix + "observed-freshness",
                  std::string(to_token(branch.observation.freshness)));
        out.field(branch_prefix + "interlock-verdict",
                  std::string(to_token(branch.interlocks_summary.verdict)));
        out.field(branch_prefix + "permission-verdict",
                  std::string(to_token(branch.permission.verdict)));
        out.field(branch_prefix + "unresolved-attempt", branch.unresolved_attempt);
      }
      ++pdu_index;
    }
    out.field("pdus", static_cast<std::uint64_t>(pdus.size()));
  }

  const EngineStatus status = engine.status();
  out.field("store-generation", status.store_generation.value());
  out.field("incarnation", status.incarnation.value());
  out.field("authority-epoch", status.authority_epoch.value());
  out.field("tick", status.current_tick.value());
  out.field("state-digest", engine.state_digest().to_hex());
  out.finish();
  return kExitOk;
}

int verb_branch(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  Output out(args.json, args.quiet);

  if (args.action == "add") {
    const auto pdu = pdu_id(args);
    if (!pdu.ok()) {
      return refuse(pdu.status(), args);
    }
    const auto branch = branch_id(args);
    if (!branch.ok()) {
      return refuse(branch.status(), args);
    }
    const auto generation = counter<BranchGenerationTag>(args, "generation");
    if (!generation.ok()) {
      return refuse(generation.status(), args);
    }
    BranchDefinition definition;
    definition.id = branch.value();
    definition.pdu = pdu.value();
    definition.generation = generation.value();
    definition.label = args.get("label");
    definition.registered_at = LogicalTick::from(number(args, "tick", 1, false).value_or(1));
    if (args.has("lifecycle") && !parse_lifecycle_state(args.get("lifecycle"), definition.lifecycle)) {
      return usage_error("unrecognized --lifecycle");
    }
    for (const std::string& text : args.get_all("interlock")) {
      const auto id = InterlockId::parse(text);
      if (!id.ok()) {
        return refuse(id.status(), args);
      }
      definition.required_interlocks.push_back(id.value());
    }
    if (args.has("continuous-mA")) {
      const auto raw = parse_u64(args.get("continuous-mA"));
      if (!raw.ok()) {
        return refuse(raw.status(), args);
      }
      definition.limits.continuous_current =
          CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
    }
    if (args.has("peak-mA")) {
      const auto raw = parse_u64(args.get("peak-mA"));
      if (!raw.ok()) {
        return refuse(raw.status(), args);
      }
      definition.limits.peak_current =
          CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
    }
    if (args.has("power-mW")) {
      const auto raw = parse_u64(args.get("power-mW"));
      if (!raw.ok()) {
        return refuse(raw.status(), args);
      }
      definition.limits.power =
          PowerSample::known(Power::from_raw(static_cast<std::int64_t>(raw.value())));
    }
    if (args.has("limit-issuer")) {
      const auto issuer = identifier<IssuerIdTag>(args, "limit-issuer");
      if (!issuer.ok()) {
        return refuse(issuer.status(), args);
      }
      definition.limits.provenance.issuer = issuer.value();
      const auto authority = identifier<AuthorityIdTag>(args, "limit-authority");
      if (!authority.ok()) {
        return refuse(authority.status(), args);
      }
      definition.limits.provenance.authority = authority.value();
      const auto epoch = counter<AuthorityEpochTag>(args, "limit-epoch", false);
      if (!epoch.ok()) {
        return refuse(epoch.status(), args);
      }
      definition.limits.provenance.epoch = epoch.value();
      definition.limits.provenance.stated_at = definition.registered_at;
      definition.limits.revision = StateRevision::from(1);
    }
    const Status status = engine.register_branch(definition);
    if (!status.ok()) {
      return refuse(status, args);
    }
    const auto snapshot = engine.inspect_branch(pdu.value(), branch.value());
    if (!snapshot.ok()) {
      return refuse(snapshot.status(), args);
    }
    report_branch(out, snapshot.value());
    out.finish();
    return kExitOk;
  }

  if (args.action == "show" || args.action.empty()) {
    const auto pdu = pdu_id(args);
    if (!pdu.ok()) {
      return refuse(pdu.status(), args);
    }
    const auto branch = branch_id(args);
    if (!branch.ok()) {
      return refuse(branch.status(), args);
    }
    const auto snapshot = engine.inspect_branch(pdu.value(), branch.value());
    if (!snapshot.ok()) {
      return refuse(snapshot.status(), args);
    }
    report_branch(out, snapshot.value());
    out.finish();
    return kExitOk;
  }

  if (args.action == "limits") {
    LimitUpdateRequest request;
    const auto pdu = pdu_id(args);
    const auto branch = branch_id(args);
    if (!pdu.ok()) {
      return refuse(pdu.status(), args);
    }
    if (!branch.ok()) {
      return refuse(branch.status(), args);
    }
    request.pdu = pdu.value();
    request.branch = branch.value();
    const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation", false);
    const auto branch_generation = counter<BranchGenerationTag>(args, "generation");
    const auto revision = counter<StateRevisionTag>(args, "revision");
    const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
    if (!branch_generation.ok()) {
      return refuse(branch_generation.status(), args);
    }
    if (!revision.ok()) {
      return refuse(revision.status(), args);
    }
    if (!epoch.ok()) {
      return refuse(epoch.status(), args);
    }
    request.branch_generation = branch_generation.value();
    request.planned_revision = revision.value();
    request.epoch = epoch.value();
    // The limit update states the PDU generation of the branch it targets when
    // the caller does not name one.
    const auto snapshot = engine.inspect_branch(pdu.value(), branch.value());
    if (!snapshot.ok()) {
      return refuse(snapshot.status(), args);
    }
    request.pdu_generation =
        pdu_generation.ok() && pdu_generation.value().is_set() ? pdu_generation.value()
                                                              : snapshot.value().pdu_generation;
    const auto issuer = identifier<IssuerIdTag>(args, "limit-issuer");
    if (!issuer.ok()) {
      return refuse(issuer.status(), args);
    }
    request.limits.provenance.issuer = issuer.value();
    if (args.has("continuous-mA")) {
      const auto raw = parse_u64(args.get("continuous-mA"));
      if (!raw.ok()) {
        return refuse(raw.status(), args);
      }
      request.limits.continuous_current =
          CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
    }
    if (args.has("peak-mA")) {
      const auto raw = parse_u64(args.get("peak-mA"));
      if (!raw.ok()) {
        return refuse(raw.status(), args);
      }
      request.limits.peak_current =
          CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
    }
    if (args.has("power-mW")) {
      const auto raw = parse_u64(args.get("power-mW"));
      if (!raw.ok()) {
        return refuse(raw.status(), args);
      }
      request.limits.power =
          PowerSample::known(Power::from_raw(static_cast<std::int64_t>(raw.value())));
    }
    const Status status = engine.update_limits(request);
    if (!status.ok()) {
      return refuse(status, args);
    }
    const auto updated = engine.inspect_branch(pdu.value(), branch.value());
    if (!updated.ok()) {
      return refuse(updated.status(), args);
    }
    report_branch(out, updated.value());
    out.finish();
    return kExitOk;
  }

  if (args.action == "enable" || args.action == "disable") {
    auto request = control_request(args);
    if (!request.ok()) {
      return report_option_failure(request.status(), args);
    }
    request.value().intent =
        args.action == "enable" ? CommandIntent::energize : CommandIntent::de_energize;
    const auto pdu = pdu_id(args);
    const auto branch = branch_id(args);
    if (!pdu.ok() || !branch.ok()) {
      return usage_error("--pdu and --branch are required");
    }
    const Status ticked = settle_tick(engine, args);
    if (!ticked.ok()) {
      return refuse(ticked, args);
    }
    if (request.value().requested_at < engine.current_tick()) {
      request.value().requested_at = engine.current_tick();
    }
    const auto decision = engine.evaluate(request.value());
    report_decision(out, decision.value());
    if (!decision.value().eligible) {
      out.finish();
      return refuse(Status::failure(decision.value().code, decision.value().detail), args);
    }
    auto adapter = make_adapter(args, engine, pdu.value(), branch.value());
    if (!adapter.ok()) {
      return refuse(adapter.status(), args);
    }
    const auto issued = engine.issue(request.value(), adapter.value());
    if (!issued.ok()) {
      out.finish();
      return refuse(issued.status(), args);
    }
    report_attempt(out, issued.value());
    out.field("adapter", std::string("synthetic"));
    if (args.verify) {
      const auto verified = engine.verify_with_adapter(issued.value().id, adapter.value());
      if (!verified.ok()) {
        out.finish();
        return refuse(verified.status(), args);
      }
      out.field("verify-effect", std::string(to_token(verified.value().effect)));
      out.field("verify-code", std::string(to_token(verified.value().code)));
      out.field("verify-state-updated", verified.value().state_updated);
      out.field("verify-detail", verified.value().detail);
    }
    out.finish();
    return kExitOk;
  }

  return usage_error("unknown branch action");
}

int verb_lifecycle(const Args& args) {
  if (args.action != "set") {
    return usage_error("lifecycle set ...");
  }
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  LifecycleRequest request;
  const auto pdu = pdu_id(args);
  if (!pdu.ok()) {
    return refuse(pdu.status(), args);
  }
  request.pdu = pdu.value();
  if (args.has("branch")) {
    const auto branch = branch_id(args);
    if (!branch.ok()) {
      return refuse(branch.status(), args);
    }
    request.branch = branch.value();
  }
  const std::string target = args.get("to");
  if (!parse_lifecycle_state(target, request.to)) {
    return usage_error("--to must name a lifecycle state");
  }
  const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
  const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation");
  const auto branch_generation = counter<BranchGenerationTag>(args, "branch-generation", false);
  const auto revision = counter<StateRevisionTag>(args, "revision");
  if (!epoch.ok()) {
    return refuse(epoch.status(), args);
  }
  if (!pdu_generation.ok()) {
    return refuse(pdu_generation.status(), args);
  }
  if (!revision.ok()) {
    return refuse(revision.status(), args);
  }
  request.epoch = epoch.value();
  request.pdu_generation = pdu_generation.value();
  request.branch_generation = branch_generation.value();
  request.planned_revision = revision.value();
  request.actor = ActorId::parse(args.get("actor", "cli")).value();
  request.requested_at = LogicalTick::from(number(args, "tick", 1, false).value_or(1));
  const Status ticked = settle_tick(engine, args);
  if (!ticked.ok()) {
    return refuse(ticked, args);
  }
  if (request.requested_at < engine.current_tick()) {
    request.requested_at = engine.current_tick();
  }
  const Status status = engine.transition_lifecycle(request);
  if (!status.ok()) {
    return refuse(status, args);
  }
  Output out(args.json, args.quiet);
  out.field("pdu", request.pdu.value());
  if (!request.branch.empty()) {
    out.field("branch", request.branch.value());
  }
  out.field("lifecycle", std::string(to_token(request.to)));
  out.finish();
  return kExitOk;
}

int verb_evaluate(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  auto request = control_request(args);
  if (!request.ok()) {
    return report_option_failure(request.status(), args);
  }
  const Status ticked = settle_tick(engine, args);
  if (!ticked.ok()) {
    return refuse(ticked, args);
  }
  if (request.value().requested_at < engine.current_tick()) {
    request.value().requested_at = engine.current_tick();
  }
  const auto decision = engine.evaluate(request.value());
  Output out(args.json, args.quiet);
  report_decision(out, decision.value());
  out.finish();
  return decision.value().eligible ? kExitOk : kExitRefused;
}

int verb_issue(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  auto request = control_request(args);
  if (!request.ok()) {
    return report_option_failure(request.status(), args);
  }
  const auto pdu = pdu_id(args);
  const auto branch = branch_id(args);
  if (!pdu.ok() || !branch.ok()) {
    return usage_error("--pdu and --branch are required");
  }
  const Status ticked = settle_tick(engine, args);
  if (!ticked.ok()) {
    return refuse(ticked, args);
  }
  if (request.value().requested_at < engine.current_tick()) {
    request.value().requested_at = engine.current_tick();
  }
  const auto decision = engine.evaluate(request.value());
  Output out(args.json, args.quiet);
  report_decision(out, decision.value());
  if (!decision.value().eligible) {
    out.finish();
    return refuse(Status::failure(decision.value().code, decision.value().detail), args);
  }
  auto adapter = make_adapter(args, engine, pdu.value(), branch.value());
  if (!adapter.ok()) {
    return refuse(adapter.status(), args);
  }
  const auto issued = engine.issue(request.value(), adapter.value());
  if (!issued.ok()) {
    out.finish();
    return refuse(issued.status(), args);
  }
  report_attempt(out, issued.value());
  out.field("adapter", std::string("synthetic"));
  out.note("adapter=synthetic SYNTHETIC: no hardware was involved");
  if (args.verify) {
    const auto verified = engine.verify_with_adapter(issued.value().id, adapter.value());
    if (!verified.ok()) {
      out.finish();
      return refuse(verified.status(), args);
    }
    out.field("verify-effect", std::string(to_token(verified.value().effect)));
    out.field("verify-code", std::string(to_token(verified.value().code)));
    out.field("verify-state-updated", verified.value().state_updated);
    out.field("verify-detail", verified.value().detail);
    const auto snapshot = engine.inspect_branch(pdu.value(), branch.value());
    if (snapshot.ok()) {
      out.field("verified", std::string(to_token(snapshot.value().verified.condition.state())));
    }
  }
  out.finish();
  return kExitOk;
}

int verb_attempts(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  Output out(args.json, args.quiet);
  if (args.has("attempt")) {
    const auto id = counter<AttemptIdTag>(args, "attempt");
    if (!id.ok()) {
      return refuse(id.status(), args);
    }
    const auto record = engine.attempt(id.value());
    if (!record.ok()) {
      return refuse(record.status(), args);
    }
    report_attempt(out, record.value());
    out.finish();
    return kExitOk;
  }
  if (args.has("key")) {
    const auto key = identifier<IdempotencyKeyTag>(args, "key");
    if (!key.ok()) {
      return refuse(key.status(), args);
    }
    const auto record = engine.attempt_by_key(key.value());
    if (!record.ok()) {
      return refuse(record.status(), args);
    }
    report_attempt(out, record.value());
    out.finish();
    return kExitOk;
  }
  const auto limit = number(args, "limit", kDefaultListLimit, false);
  if (!limit.ok()) {
    return refuse(limit.status(), args);
  }
  if (limit.value() > kMaxListLimit) {
    return usage_error("--limit must not exceed 10000");
  }
  const auto records = engine.attempts(static_cast<std::size_t>(limit.value()));
  out.field("count", static_cast<std::uint64_t>(records.size()));
  std::uint64_t index = 0;
  for (const AttemptRecord& record : records) {
    const std::string prefix = "attempt-" + std::to_string(index) + "-";
    out.field(prefix + "id", record.id.value());
    out.field(prefix + "key", record.key.value());
    out.field(prefix + "branch", record.branch.value());
    out.field(prefix + "intent", std::string(to_token(record.intent)));
    out.field(prefix + "outcome", std::string(to_token(record.outcome)));
    out.field(prefix + "effect", std::string(to_token(record.effect)));
    out.field(prefix + "code", std::string(to_token(record.code)));
    out.field(prefix + "dispatched", record.dispatched);
    ++index;
  }
  out.finish();
  return kExitOk;
}

int verb_verify(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  const auto id = counter<AttemptIdTag>(args, "attempt");
  if (!id.ok()) {
    return refuse(id.status(), args);
  }
  const auto record = engine.attempt(id.value());
  if (!record.ok()) {
    return refuse(record.status(), args);
  }
  Output out(args.json, args.quiet);
  if (args.read_back) {
    auto adapter = make_adapter(args, engine, record.value().pdu, record.value().branch);
    if (!adapter.ok()) {
      return refuse(adapter.status(), args);
    }
    const auto verified = engine.verify_with_adapter(id.value(), adapter.value());
    if (!verified.ok()) {
      return refuse(verified.status(), args);
    }
    out.field("adapter", std::string("synthetic"));
    out.field("effect", std::string(to_token(verified.value().effect)));
    out.field("code", std::string(to_token(verified.value().code)));
    out.field("state-updated", verified.value().state_updated);
    out.field("detail", verified.value().detail);
    out.field("observation-used", verified.value().observation_used);
    out.field("observation", verified.value().observation.value());
    out.finish();
    return kExitOk;
  }
  const auto verified = engine.verify(id.value());
  if (!verified.ok()) {
    return refuse(verified.status(), args);
  }
  out.field("effect", std::string(to_token(verified.value().effect)));
  out.field("code", std::string(to_token(verified.value().code)));
  out.field("state-updated", verified.value().state_updated);
  out.field("detail", verified.value().detail);
  out.finish();
  return kExitOk;
}

int verb_revalidate(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  TelemetryObservation observation;
  const auto pdu = pdu_id(args);
  const auto branch = branch_id(args);
  if (!pdu.ok() || !branch.ok()) {
    return usage_error("--pdu and --branch are required");
  }
  observation.pdu = pdu.value();
  observation.branch = branch.value();
  const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation");
  const auto branch_generation = counter<BranchGenerationTag>(args, "branch-generation");
  const auto source = identifier<SourceIdTag>(args, "source");
  const auto sequence = counter<SequenceNumberTag>(args, "sequence");
  const auto tick = counter<LogicalTickTag>(args, "tick");
  if (!pdu_generation.ok() || !branch_generation.ok() || !source.ok() || !sequence.ok() ||
      !tick.ok()) {
    return usage_error("--pdu-generation, --branch-generation, --source, --sequence and --tick "
                       "are required");
  }
  observation.pdu_generation = pdu_generation.value();
  observation.branch_generation = branch_generation.value();
  observation.source = source.value();
  observation.sequence = sequence.value();
  observation.taken_at = Instant::logical(tick.value());
  if (!parse_branch_condition(args.get("condition"), observation.condition)) {
    return usage_error("--condition must name a branch condition");
  }
  if (args.has("quality") && !parse_evidence_quality(args.get("quality"), observation.quality)) {
    return usage_error("--quality must name an evidence quality");
  } else if (!args.has("quality")) {
    observation.quality = EvidenceQuality::good;
  }
  if (args.has("current-mA")) {
    const auto raw = parse_u64(args.get("current-mA"));
    if (!raw.ok()) {
      return refuse(raw.status(), args);
    }
    observation.current =
        CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
  }
  if (args.has("voltage-mV")) {
    const auto raw = parse_u64(args.get("voltage-mV"));
    if (!raw.ok()) {
      return refuse(raw.status(), args);
    }
    observation.voltage =
        VoltageSample::known(Voltage::from_raw(static_cast<std::int64_t>(raw.value())));
  }
  if (args.has("power-mW")) {
    const auto raw = parse_u64(args.get("power-mW"));
    if (!raw.ok()) {
      return refuse(raw.status(), args);
    }
    observation.power =
        PowerSample::known(Power::from_raw(static_cast<std::int64_t>(raw.value())));
  }
  const Status ticked = settle_tick(engine, args);
  if (!ticked.ok()) {
    return refuse(ticked, args);
  }
  const auto recorded = engine.revalidate(pdu.value(), branch.value(), observation);
  if (!recorded.ok()) {
    return refuse(recorded.status(), args);
  }
  Output out(args.json, args.quiet);
  out.field("observation", recorded.value().value());
  out.field("condition", std::string(to_token(observation.condition)));
  out.note("revalidated=1");
  out.finish();
  return kExitOk;
}

int verb_observe(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  TelemetryObservation observation;
  const auto pdu = pdu_id(args);
  const auto branch = branch_id(args);
  if (!pdu.ok() || !branch.ok()) {
    return usage_error("--pdu and --branch are required");
  }
  observation.pdu = pdu.value();
  observation.branch = branch.value();
  const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation");
  const auto branch_generation = counter<BranchGenerationTag>(args, "branch-generation");
  const auto source = identifier<SourceIdTag>(args, "source");
  const auto sequence = counter<SequenceNumberTag>(args, "sequence");
  const auto tick = counter<LogicalTickTag>(args, "tick");
  if (!pdu_generation.ok() || !branch_generation.ok() || !source.ok() || !sequence.ok() ||
      !tick.ok()) {
    return usage_error("--pdu-generation, --branch-generation, --source, --sequence and --tick "
                       "are required");
  }
  observation.pdu_generation = pdu_generation.value();
  observation.branch_generation = branch_generation.value();
  observation.source = source.value();
  observation.sequence = sequence.value();
  observation.taken_at = Instant::logical(tick.value());
  if (!parse_branch_condition(args.get("condition"), observation.condition)) {
    return usage_error("--condition must name a branch condition");
  }
  observation.quality = EvidenceQuality::good;
  if (args.has("quality") && !parse_evidence_quality(args.get("quality"), observation.quality)) {
    return usage_error("--quality must name an evidence quality");
  }
  if (args.has("current-mA")) {
    const auto raw = parse_u64(args.get("current-mA"));
    if (!raw.ok()) {
      return refuse(raw.status(), args);
    }
    observation.current =
        CurrentSample::known(Current::from_raw(static_cast<std::int64_t>(raw.value())));
  }
  const Status ticked = settle_tick(engine, args);
  if (!ticked.ok()) {
    return refuse(ticked, args);
  }
  const auto recorded = engine.record_observation(observation);
  if (!recorded.ok()) {
    return refuse(recorded.status(), args);
  }
  Output out(args.json, args.quiet);
  out.field("observation", recorded.value().value());
  out.field("condition", std::string(to_token(observation.condition)));
  out.finish();
  return kExitOk;
}

int verb_history(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  HistoryQuery query;
  const auto limit = number(args, "limit", kDefaultListLimit, false);
  if (!limit.ok()) {
    return refuse(limit.status(), args);
  }
  if (limit.value() > kMaxListLimit) {
    return usage_error("--limit must not exceed 10000");
  }
  query.limit = static_cast<std::size_t>(limit.value());
  if (args.has("pdu")) {
    const auto id = pdu_id(args);
    if (!id.ok()) {
      return refuse(id.status(), args);
    }
    query.has_pdu = true;
    query.pdu = id.value();
  }
  if (args.has("branch")) {
    const auto id = branch_id(args);
    if (!id.ok()) {
      return refuse(id.status(), args);
    }
    query.has_branch = true;
    query.branch = id.value();
  }
  if (args.has("attempt")) {
    const auto id = counter<AttemptIdTag>(args, "attempt");
    if (!id.ok()) {
      return refuse(id.status(), args);
    }
    query.has_attempt = true;
    query.attempt = id.value();
  }
  if (args.has("kind")) {
    AuditKind kind = AuditKind::engine_opened;
    if (!parse_audit_kind(args.get("kind"), kind)) {
      return usage_error("unrecognized --kind");
    }
    query.has_kind = true;
    query.kind = kind;
  }
  const auto entries = engine.history(query);
  Output out(args.json, args.quiet);
  out.field("count", static_cast<std::uint64_t>(entries.size()));
  for (const AuditEntry& entry : entries) {
    const std::string prefix = "entry-" + std::to_string(entry.sequence.value()) + "-";
    out.field(prefix + "kind", std::string(to_token(entry.kind)));
    out.field(prefix + "tick", entry.tick.value());
    out.field(prefix + "code", std::string(to_token(entry.code)));
    if (!entry.pdu.empty()) {
      out.field(prefix + "pdu", entry.pdu.value());
    }
    if (!entry.branch.empty()) {
      out.field(prefix + "branch", entry.branch.value());
    }
    if (entry.attempt.is_set()) {
      out.field(prefix + "attempt", entry.attempt.value());
    }
    if (!entry.detail.empty()) {
      out.field(prefix + "detail", entry.detail);
    }
  }
  out.finish();
  return kExitOk;
}

int verb_store_audit(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  const EngineStatus status = engine.status();
  const StoreAudit audit = status.store;
  Output out(args.json, args.quiet);
  out.field("durable", audit.durable);
  out.field("open", audit.open);
  out.field("read-only", audit.read_only);
  out.field("store", audit.path.empty() ? std::string("(in memory)") : audit.path);
  out.field("format-version", static_cast<std::uint64_t>(audit.format_version));
  out.field("generation", audit.generation.value());
  out.field("published-generation", audit.published_generation.value());
  out.field("min-accepted-generation", audit.min_accepted_generation.value());
  out.field("incarnation", audit.incarnation.value());
  out.field("stored-incarnation", audit.stored_incarnation.value());
  out.field("open-count", audit.open_count);
  out.field("publication-count", audit.publication_count);
  out.field("head-writes", audit.head_writes);
  out.field("slot-writes", audit.slot_writes);
  out.field("flushes", audit.flushes);
  out.field("readback-verifications", audit.readback_verifications);
  out.field("bytes-written", audit.bytes_written);
  out.field("bytes-read", audit.bytes_read);
  out.field("crc-mismatches", audit.crc_mismatches);
  out.field("rejected-open-attempts", audit.rejected_open_attempts);
  out.field("fenced-writes", audit.fenced_writes);
  out.field("head-records-valid", static_cast<std::uint64_t>(audit.head_records_valid));
  out.field("head-slot", static_cast<std::uint64_t>(audit.head_slot_index));
  out.field("exclusively-locked", audit.exclusively_locked);
  out.field("rollback-fence-armed", audit.rollback_fence_armed);
  out.field("last-published-digest", audit.last_published_digest.to_hex());
  out.field("state-digest", audit.state_digest.to_hex());
  out.field("pdus", static_cast<std::uint64_t>(status.pdu_count));
  out.field("branches", static_cast<std::uint64_t>(status.branch_count));
  out.field("attempts", static_cast<std::uint64_t>(status.attempt_count));
  out.field("unresolved-attempts", static_cast<std::uint64_t>(status.unresolved_attempt_count));
  out.field("idempotency-entries", static_cast<std::uint64_t>(status.idempotency_entries));
  out.field("audit-entries", static_cast<std::uint64_t>(status.audit_entries));
  out.field("audit-dropped", status.audit_dropped);
  out.field("refusals", status.refusal_count);
  out.field("dispatches", status.dispatch_count);
  out.field("verifications", status.verification_count);
  out.field("authority-epoch", status.authority_epoch.value());
  out.field("tick", status.current_tick.value());
  out.field("version", std::string(version_string));
  out.note("SYNTHETIC: adapters are deterministic simulators unless a vendor adapter is installed;"
           " no hardware is contacted by this tool");
  out.finish();
  return kExitOk;
}

int verb_epoch(const Args& args) {
  if (args.action != "adopt") {
    return usage_error("epoch adopt --epoch E");
  }
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
  if (!epoch.ok()) {
    return refuse(epoch.status(), args);
  }
  const Status status = opened.value().adopt_authority_epoch(epoch.value());
  if (!status.ok()) {
    return refuse(status, args);
  }
  Output out(args.json, args.quiet);
  out.field("authority-epoch", epoch.value().value());
  out.finish();
  return kExitOk;
}

int verb_tick(const Args& args) {
  if (args.action != "advance") {
    return usage_error("tick advance --tick T");
  }
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  const auto tick = counter<LogicalTickTag>(args, "tick");
  if (!tick.ok()) {
    return refuse(tick.status(), args);
  }
  const Status status = opened.value().advance_tick(tick.value());
  if (!status.ok()) {
    return refuse(status, args);
  }
  Output out(args.json, args.quiet);
  out.field("tick", tick.value().value());
  out.finish();
  return kExitOk;
}

int verb_grant(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  Output out(args.json, args.quiet);
  if (args.action == "add") {
    PermissionGrant grant;
    const auto id = identifier<AuthorityIdTag>(args, "grant");
    const auto issuer = identifier<IssuerIdTag>(args, "issuer");
    const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
    const auto pdu = pdu_id(args);
    const auto branch = branch_id(args);
    const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation");
    const auto branch_generation = counter<BranchGenerationTag>(args, "branch-generation");
    const auto issued = counter<LogicalTickTag>(args, "issued");
    if (!id.ok() || !issuer.ok() || !epoch.ok() || !pdu.ok() || !branch.ok() ||
        !pdu_generation.ok() || !branch_generation.ok() || !issued.ok()) {
      return usage_error("grant add requires --grant --issuer --epoch --pdu --branch "
                         "--pdu-generation --branch-generation --issued --actions");
    }
    grant.id = id.value();
    grant.issuer = issuer.value();
    grant.epoch = epoch.value();
    grant.pdu = pdu.value();
    grant.branch = branch.value();
    grant.pdu_generation = pdu_generation.value();
    grant.branch_generation = branch_generation.value();
    grant.issued_at = issued.value();
    const auto not_after = counter<LogicalTickTag>(args, "not-after", false);
    if (!not_after.ok()) {
      return refuse(not_after.status(), args);
    }
    grant.not_after = not_after.value();
    const std::string actions = args.get("actions");
    if (actions.empty()) {
      return usage_error("grant add requires --actions");
    }
    PermissionActions mask = 0;
    std::string token;
    for (std::size_t index = 0; index <= actions.size(); ++index) {
      if (index == actions.size() || actions[index] == ',') {
        PermissionAction action = PermissionAction::none;
        bool matched = false;
        const struct {
          const char* name;
          PermissionAction value;
        } kTable[] = {{"control_energize", PermissionAction::control_energize},
                      {"control_de_energize", PermissionAction::control_de_energize},
                      {"lifecycle_service", PermissionAction::lifecycle_service},
                      {"lifecycle_recovery", PermissionAction::lifecycle_recovery},
                      {"lifecycle_administrative", PermissionAction::lifecycle_administrative},
                      {"maintenance_override", PermissionAction::maintenance_override}};
        for (const auto& entry : kTable) {
          if (token == entry.name) {
            action = entry.value;
            matched = true;
            break;
          }
        }
        if (!matched) {
          return usage_error("unrecognized action '" + token + "'");
        }
        mask = static_cast<PermissionActions>(mask | action_mask(action));
        token.clear();
      } else {
        token.push_back(actions[index]);
      }
    }
    grant.actions = mask;
    const Status status = engine.record_grant(grant);
    if (!status.ok()) {
      return refuse(status, args);
    }
    out.field("grant", grant.id.value());
    out.field("actions", to_token(grant.actions));
    out.finish();
    return kExitOk;
  }
  if (args.action == "revoke") {
    const auto id = identifier<AuthorityIdTag>(args, "grant");
    const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
    const auto tick = counter<LogicalTickTag>(args, "tick");
    if (!id.ok() || !epoch.ok() || !tick.ok()) {
      return usage_error("grant revoke requires --grant --epoch --tick");
    }
    const Status status = engine.revoke_grant(id.value(), epoch.value(), tick.value());
    if (!status.ok()) {
      return refuse(status, args);
    }
    out.field("grant", id.value().value());
    out.field("revoked", true);
    out.finish();
    return kExitOk;
  }
  return usage_error("unknown grant action");
}

int verb_override(const Args& args) {
  if (args.action != "add") {
    return usage_error("override add ...");
  }
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  MaintenanceOverride value;
  const auto id = identifier<AuthorityIdTag>(args, "override");
  const auto issuer = identifier<IssuerIdTag>(args, "issuer");
  const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
  const auto pdu = pdu_id(args);
  const auto branch = branch_id(args);
  const auto pdu_generation = counter<PduGenerationTag>(args, "pdu-generation");
  const auto branch_generation = counter<BranchGenerationTag>(args, "branch-generation");
  const auto issued = counter<LogicalTickTag>(args, "issued");
  const auto not_after = counter<LogicalTickTag>(args, "not-after");
  if (!id.ok() || !issuer.ok() || !epoch.ok() || !pdu.ok() || !branch.ok() ||
      !pdu_generation.ok() || !branch_generation.ok() || !issued.ok() || !not_after.ok()) {
    return usage_error("override add requires --override --issuer --epoch --pdu --branch "
                       "--pdu-generation --branch-generation --issued --not-after");
  }
  value.id = id.value();
  value.issuer = issuer.value();
  value.epoch = epoch.value();
  value.pdu = pdu.value();
  value.branch = branch.value();
  value.pdu_generation = pdu_generation.value();
  value.branch_generation = branch_generation.value();
  value.issued_at = issued.value();
  value.not_after = not_after.value();
  const Status status = opened.value().record_maintenance_override(value);
  if (!status.ok()) {
    return refuse(status, args);
  }
  Output out(args.json, args.quiet);
  out.field("override", value.id.value());
  out.finish();
  return kExitOk;
}

int verb_interlock(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  PduControlEngine& engine = opened.value();
  Output out(args.json, args.quiet);
  if (args.action == "declare") {
    InterlockDeclaration declaration;
    const auto id = identifier<InterlockIdTag>(args, "interlock");
    const auto pdu = pdu_id(args);
    const auto branch = branch_id(args);
    const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
    const auto tick = counter<LogicalTickTag>(args, "tick");
    if (!id.ok() || !pdu.ok() || !branch.ok() || !epoch.ok() || !tick.ok()) {
      return usage_error("interlock declare requires --interlock --pdu --branch --epoch --tick");
    }
    declaration.id = id.value();
    declaration.pdu = pdu.value();
    declaration.branch = branch.value();
    declaration.epoch = epoch.value();
    declaration.declared_at = tick.value();
    if (args.has("class") && !parse_obligation_class(args.get("class"), declaration.klass)) {
      return usage_error("--class must be protected or advisory");
    }
    const Status status = engine.declare_interlock(declaration);
    if (!status.ok()) {
      return refuse(status, args);
    }
    out.field("interlock", declaration.id.value());
    out.field("class", std::string(to_token(declaration.klass)));
    out.finish();
    return kExitOk;
  }
  if (args.action == "report") {
    InterlockStatus status_value;
    const auto id = identifier<InterlockIdTag>(args, "interlock");
    const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
    const auto tick = counter<LogicalTickTag>(args, "tick");
    if (!id.ok() || !epoch.ok() || !tick.ok()) {
      return usage_error("interlock report requires --interlock --state --epoch --tick");
    }
    status_value.id = id.value();
    status_value.epoch = epoch.value();
    status_value.updated_at = tick.value();
    if (!parse_interlock_state(args.get("state"), status_value.state)) {
      return usage_error("--state must be satisfied, open or unknown");
    }
    if (args.has("clearance")) {
      const auto clearance = identifier<AuthorityIdTag>(args, "clearance");
      if (!clearance.ok()) {
        return refuse(clearance.status(), args);
      }
      status_value.clearance = clearance.value();
    }
    const Status status = engine.report_interlock(status_value);
    if (!status.ok()) {
      return refuse(status, args);
    }
    out.field("interlock", status_value.id.value());
    out.field("state", std::string(to_token(status_value.state)));
    out.finish();
    return kExitOk;
  }
  return usage_error("unknown interlock action");
}

int verb_resolve(const Args& args) {
  auto opened = open_engine(args);
  if (!opened.ok()) {
    return refuse(opened.status(), args);
  }
  const auto id = counter<AttemptIdTag>(args, "attempt");
  const auto actor = identifier<ActorIdTag>(args, "actor");
  const auto epoch = counter<AuthorityEpochTag>(args, "epoch");
  const auto tick = counter<LogicalTickTag>(args, "tick");
  if (!id.ok() || !actor.ok() || !epoch.ok() || !tick.ok()) {
    return usage_error("resolve requires --attempt --resolution --actor --epoch --tick");
  }
  AttemptResolution resolution = AttemptResolution::cancelled;
  if (!parse_attempt_resolution(args.get("resolution"), resolution)) {
    return usage_error("--resolution must be cancelled or superseded");
  }
  const Status status =
      opened.value().resolve_attempt(id.value(), resolution, actor.value(), epoch.value(), tick.value());
  if (!status.ok()) {
    return refuse(status, args);
  }
  Output out(args.json, args.quiet);
  out.field("attempt", id.value().value());
  out.field("resolution", std::string(to_token(resolution)));
  out.finish();
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  Args args;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help" || argument == "-h") {
      args.help = true;
    } else if (argument == "--version") {
      args.version = true;
    } else if (argument == "--json") {
      args.json = true;
    } else if (argument == "--quiet") {
      args.quiet = true;
    } else if (argument == "--verify") {
      args.verify = true;
    } else if (argument == "--read-back") {
      args.read_back = true;
    } else if (argument.size() > 2 && argument[0] == '-' && argument[1] == '-') {
      const std::string key = argument.substr(2);
      if (index + 1 >= argc) {
        return usage_error("--" + key + " needs a value");
      }
      const std::string value = argv[++index];
      if (key == "store") {
        args.store = value;
      } else {
        args.options.emplace_back(key, value);
      }
    } else if (args.verb.empty()) {
      args.verb = argument;
    } else if (args.action.empty()) {
      args.action = argument;
    } else {
      return usage_error("unexpected argument '" + argument + "'");
    }
  }
  if (args.version) {
    std::cout << "pdu-control " << version_string << " (store format " << store_format_version
              << ")\n";
    return kExitOk;
  }
  if (args.help) {
    std::cout << kUsage;
    return kExitOk;
  }
  if (args.verb.empty()) {
    std::cout << kUsage;
    return kExitUsage;
  }
  if (args.verb == "init") {
    return verb_init(args);
  }
  if (args.verb == "inspect") {
    return verb_inspect(args);
  }
  if (args.verb == "branch") {
    return verb_branch(args);
  }
  if (args.verb == "lifecycle") {
    return verb_lifecycle(args);
  }
  if (args.verb == "evaluate") {
    return verb_evaluate(args);
  }
  if (args.verb == "issue") {
    return verb_issue(args);
  }
  if (args.verb == "attempts") {
    return verb_attempts(args);
  }
  if (args.verb == "verify") {
    return verb_verify(args);
  }
  if (args.verb == "revalidate") {
    return verb_revalidate(args);
  }
  if (args.verb == "observe") {
    return verb_observe(args);
  }
  if (args.verb == "history") {
    return verb_history(args);
  }
  if (args.verb == "store-audit") {
    return verb_store_audit(args);
  }
  if (args.verb == "epoch") {
    return verb_epoch(args);
  }
  if (args.verb == "tick") {
    return verb_tick(args);
  }
  if (args.verb == "grant") {
    return verb_grant(args);
  }
  if (args.verb == "override") {
    return verb_override(args);
  }
  if (args.verb == "interlock") {
    return verb_interlock(args);
  }
  if (args.verb == "resolve") {
    return verb_resolve(args);
  }
  std::cout << kUsage;
  return kExitUsage;
}
