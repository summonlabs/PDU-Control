#include "detail/serialization.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "detail/access.hpp"
#include "detail/codec.hpp"
#include "pdu_control/version.hpp"

namespace pdu_control::detail {
namespace {

constexpr std::size_t kMaxIdentifierBytes = 96;
constexpr std::size_t kMaxLabelBytes = 160;
constexpr std::size_t kMaxAuditDetailBytes = 192;
constexpr std::size_t kMaxAdapterDetailBytes = 256;
/// magic (8) + version (4) + generation (8) + incarnation (8) + body length (4)
constexpr std::size_t kEnvelopeBytes = 8 + 4 + 8 + 8 + 4;

/// Enumerators are written as their underlying value and range-checked on read,
/// so a corrupt or hostile byte can never become an out-of-range enumerator.
Status check_range(std::uint64_t value, std::uint64_t maximum, std::string_view what) {
  if (value > maximum) {
    return Status::failure(StatusCode::store_malformed,
                           std::string(what) + " has out-of-range value " + std::to_string(value));
  }
  return Status::success();
}

// --- primitives ------------------------------------------------------------
//
// Every text field written here was validated against its own bound when it
// entered the model, and every count was checked against its own bound at the
// same time, so the writer-level bound cannot fire on a well-formed state. The
// writer bound is still passed so that a state assembled by a future caller with
// a wider bound is refused rather than truncated; `encode_state` additionally
// refuses a payload larger than the format allows.

template <typename Tag>
void write_id(Writer& writer, const Identifier<Tag>& id) {
  (void)writer.text(id.value(), kMaxIdentifierBytes);
}

template <typename Tag>
Result<Identifier<Tag>> read_id(Reader& reader) {
  Result<std::string> text = reader.text(kMaxIdentifierBytes);
  if (!text.ok()) {
    return text.status();
  }
  // An absent identity is written as an empty string and read back as the unset
  // identity. It is not a malformed field: several references are legitimately
  // optional (an owner, a protection zone, an interlock clearance).
  if (text.value().empty()) {
    return Identifier<Tag>::unset();
  }
  Result<Identifier<Tag>> id = Identifier<Tag>::parse(text.value());
  if (!id.ok()) {
    return Status::failure(StatusCode::store_malformed,
                           "the stored text is not a valid identity: " + id.status().message());
  }
  return id.value();
}

template <typename Tag>
void write_counter(Writer& writer, const Counter<Tag>& counter) {
  writer.u64(counter.value());
}

template <typename Tag>
Result<Counter<Tag>> read_counter(Reader& reader) {
  Result<std::uint64_t> value = reader.u64();
  if (!value.ok()) {
    return value.status();
  }
  return Counter<Tag>::from(value.value());
}

template <typename Q>
void write_sample(Writer& writer, const Sample<Q>& sample) {
  writer.u8(static_cast<std::uint8_t>(sample.state()));
  if (sample.has_value()) {
    writer.i64(sample.value().raw());
  }
}

template <typename Q>
Result<Sample<Q>> read_sample(Reader& reader) {
  Result<std::uint8_t> state = reader.u8();
  if (!state.ok()) {
    return state.status();
  }
  const Status range = check_range(state.value(),
                                   static_cast<std::uint64_t>(SampleState::unsupported),
                                   "sample state");
  if (!range.ok()) {
    return range;
  }
  const auto decoded = static_cast<SampleState>(state.value());
  if (decoded == SampleState::known) {
    Result<std::int64_t> raw = reader.i64();
    if (!raw.ok()) {
      return raw.status();
    }
    return Sample<Q>::known(Q::from_raw(raw.value()));
  }
  if (decoded == SampleState::unavailable) {
    return Sample<Q>::unavailable();
  }
  if (decoded == SampleState::unsupported) {
    return Sample<Q>::unsupported();
  }
  return Sample<Q>::unknown();
}

void write_condition_sample(Writer& writer, const Sample<BranchCondition>& sample) {
  writer.u8(static_cast<std::uint8_t>(sample.state()));
  if (sample.has_value()) {
    writer.u8(static_cast<std::uint8_t>(sample.value()));
  }
}

Result<Sample<BranchCondition>> read_condition_sample(Reader& reader) {
  Result<std::uint8_t> state = reader.u8();
  if (!state.ok()) {
    return state.status();
  }
  const Status range = check_range(state.value(),
                                   static_cast<std::uint64_t>(SampleState::unsupported),
                                   "sample state");
  if (!range.ok()) {
    return range;
  }
  const auto decoded = static_cast<SampleState>(state.value());
  if (decoded != SampleState::known) {
    if (decoded == SampleState::unavailable) {
      return Sample<BranchCondition>::unavailable();
    }
    if (decoded == SampleState::unsupported) {
      return Sample<BranchCondition>::unsupported();
    }
    return Sample<BranchCondition>::unknown();
  }
  Result<std::uint8_t> condition = reader.u8();
  if (!condition.ok()) {
    return condition.status();
  }
  const Status condition_range =
      check_range(condition.value(), static_cast<std::uint64_t>(BranchCondition::unknown),
                  "branch condition");
  if (!condition_range.ok()) {
    return condition_range;
  }
  return Sample<BranchCondition>::known(static_cast<BranchCondition>(condition.value()));
}

void write_instant(Writer& writer, const Instant& instant) {
  writer.u8(static_cast<std::uint8_t>(instant.domain));
  writer.u64(instant.tick.value());
  writer.i64(instant.nanoseconds);
}

Result<Instant> read_instant(Reader& reader) {
  Result<std::uint8_t> domain = reader.u8();
  if (!domain.ok()) {
    return domain.status();
  }
  const Status range = check_range(domain.value(),
                                   static_cast<std::uint64_t>(ClockDomain::vendor_opaque),
                                   "clock domain");
  if (!range.ok()) {
    return range;
  }
  Result<std::uint64_t> tick = reader.u64();
  if (!tick.ok()) {
    return tick.status();
  }
  Result<std::int64_t> nanos = reader.i64();
  if (!nanos.ok()) {
    return nanos.status();
  }
  Instant instant;
  instant.domain = static_cast<ClockDomain>(domain.value());
  instant.tick = LogicalTick::from(tick.value());
  instant.nanoseconds = nanos.value();
  return instant;
}

// --- model records ---------------------------------------------------------

void write_limits(Writer& writer, const BranchLimits& limits) {
  write_sample(writer, limits.continuous_current);
  write_sample(writer, limits.peak_current);
  write_sample(writer, limits.power);
  write_id(writer, limits.provenance.issuer);
  write_id(writer, limits.provenance.authority);
  write_counter(writer, limits.provenance.epoch);
  write_counter(writer, limits.provenance.stated_at);
  write_counter(writer, limits.provenance.not_after);
  write_counter(writer, limits.revision);
}

Result<BranchLimits> read_limits(Reader& reader) {
  BranchLimits limits;
  Result<CurrentSample> continuous = read_sample<Current>(reader);
  if (!continuous.ok()) {
    return continuous.status();
  }
  limits.continuous_current = continuous.value();
  Result<CurrentSample> peak = read_sample<Current>(reader);
  if (!peak.ok()) {
    return peak.status();
  }
  limits.peak_current = peak.value();
  Result<PowerSample> power = read_sample<Power>(reader);
  if (!power.ok()) {
    return power.status();
  }
  limits.power = power.value();
  Result<IssuerId> issuer = read_id<IssuerIdTag>(reader);
  if (!issuer.ok()) {
    return issuer.status();
  }
  limits.provenance.issuer = issuer.value();
  Result<AuthorityId> authority = read_id<AuthorityIdTag>(reader);
  if (!authority.ok()) {
    return authority.status();
  }
  limits.provenance.authority = authority.value();
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  limits.provenance.epoch = epoch.value();
  Result<LogicalTick> stated = read_counter<LogicalTickTag>(reader);
  if (!stated.ok()) {
    return stated.status();
  }
  limits.provenance.stated_at = stated.value();
  Result<LogicalTick> not_after = read_counter<LogicalTickTag>(reader);
  if (!not_after.ok()) {
    return not_after.status();
  }
  limits.provenance.not_after = not_after.value();
  Result<StateRevision> revision = read_counter<StateRevisionTag>(reader);
  if (!revision.ok()) {
    return revision.status();
  }
  limits.revision = revision.value();
  return limits;
}

void write_pdu_definition(Writer& writer, const PduDefinition& definition) {
  write_id(writer, definition.id);
  write_counter(writer, definition.generation);
  writer.u8(static_cast<std::uint8_t>(definition.lifecycle));
  (void)writer.text(definition.label, kMaxLabelBytes);
  write_id(writer, definition.owner);
  write_id(writer, definition.zone);
  write_counter(writer, definition.registered_at);
}

Result<PduDefinition> read_pdu_definition(Reader& reader) {
  PduDefinition definition;
  Result<PduId> id = read_id<PduIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  definition.id = id.value();
  Result<PduGeneration> generation = read_counter<PduGenerationTag>(reader);
  if (!generation.ok()) {
    return generation.status();
  }
  definition.generation = generation.value();
  Result<std::uint8_t> lifecycle = reader.u8();
  if (!lifecycle.ok()) {
    return lifecycle.status();
  }
  const Status range = check_range(lifecycle.value(),
                                   static_cast<std::uint64_t>(LifecycleState::retired),
                                   "lifecycle state");
  if (!range.ok()) {
    return range;
  }
  definition.lifecycle = static_cast<LifecycleState>(lifecycle.value());
  Result<std::string> label = reader.text(kMaxLabelBytes);
  if (!label.ok()) {
    return label.status();
  }
  definition.label = label.value();
  Result<IssuerId> owner = read_id<IssuerIdTag>(reader);
  if (!owner.ok()) {
    return owner.status();
  }
  definition.owner = owner.value();
  Result<ProtectionZoneId> zone = read_id<ProtectionZoneIdTag>(reader);
  if (!zone.ok()) {
    return zone.status();
  }
  definition.zone = zone.value();
  Result<LogicalTick> registered = read_counter<LogicalTickTag>(reader);
  if (!registered.ok()) {
    return registered.status();
  }
  definition.registered_at = registered.value();
  return definition;
}

void write_pdu_state(Writer& writer, const PduState& state) {
  writer.u8(static_cast<std::uint8_t>(state.lifecycle));
  write_counter(writer, state.revision);
}

Result<PduState> read_pdu_state(Reader& reader) {
  PduState state;
  Result<std::uint8_t> lifecycle = reader.u8();
  if (!lifecycle.ok()) {
    return lifecycle.status();
  }
  const Status range = check_range(lifecycle.value(),
                                   static_cast<std::uint64_t>(LifecycleState::retired),
                                   "lifecycle state");
  if (!range.ok()) {
    return range;
  }
  state.lifecycle = static_cast<LifecycleState>(lifecycle.value());
  Result<StateRevision> revision = read_counter<StateRevisionTag>(reader);
  if (!revision.ok()) {
    return revision.status();
  }
  state.revision = revision.value();
  return state;
}


void write_branch_definition(Writer& writer, const BranchDefinition& definition) {
  write_id(writer, definition.id);
  write_id(writer, definition.pdu);
  write_counter(writer, definition.generation);
  writer.u8(static_cast<std::uint8_t>(definition.lifecycle));
  (void)writer.text(definition.label, kMaxLabelBytes);
  write_limits(writer, definition.limits);
  (void)writer.count(definition.required_interlocks.size(), 4096);
  for (const InterlockId& id : definition.required_interlocks) {
    write_id(writer, id);
  }
  write_counter(writer, definition.registered_at);
}

Status read_branch_definition(Reader& reader, const ModelBounds& bounds,
                              BranchDefinition& definition) {
  Result<BranchId> id = read_id<BranchIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  definition.id = id.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  definition.pdu = pdu.value();
  Result<BranchGeneration> generation = read_counter<BranchGenerationTag>(reader);
  if (!generation.ok()) {
    return generation.status();
  }
  definition.generation = generation.value();
  Result<std::uint8_t> lifecycle = reader.u8();
  if (!lifecycle.ok()) {
    return lifecycle.status();
  }
  const Status range = check_range(lifecycle.value(),
                                   static_cast<std::uint64_t>(LifecycleState::retired),
                                   "lifecycle state");
  if (!range.ok()) {
    return range;
  }
  definition.lifecycle = static_cast<LifecycleState>(lifecycle.value());
  Result<std::string> label = reader.text(kMaxLabelBytes);
  if (!label.ok()) {
    return label.status();
  }
  definition.label = label.value();
  Result<BranchLimits> limits = read_limits(reader);
  if (!limits.ok()) {
    return limits.status();
  }
  definition.limits = limits.value();
  Result<std::size_t> count = reader.count(bounds.max_required_interlocks_per_branch);
  if (!count.ok()) {
    return count.status();
  }
  definition.required_interlocks.clear();
  definition.required_interlocks.reserve(count.value());
  for (std::size_t index = 0; index < count.value(); ++index) {
    Result<InterlockId> interlock = read_id<InterlockIdTag>(reader);
    if (!interlock.ok()) {
      return interlock.status();
    }
    definition.required_interlocks.push_back(interlock.value());
  }
  Result<LogicalTick> registered = read_counter<LogicalTickTag>(reader);
  if (!registered.ok()) {
    return registered.status();
  }
  definition.registered_at = registered.value();
  return Status::success();
}

void write_observation(Writer& writer, const TelemetryObservation& observation) {
  write_counter(writer, observation.id);
  write_id(writer, observation.pdu);
  write_id(writer, observation.branch);
  write_counter(writer, observation.pdu_generation);
  write_counter(writer, observation.branch_generation);
  write_id(writer, observation.source);
  write_counter(writer, observation.sequence);
  write_instant(writer, observation.taken_at);
  write_instant(writer, observation.received_at);
  write_counter(writer, observation.accepted_tick);
  writer.u8(static_cast<std::uint8_t>(observation.quality));
  writer.u8(static_cast<std::uint8_t>(observation.condition));
  write_sample(writer, observation.current);
  write_sample(writer, observation.voltage);
  write_sample(writer, observation.power);
  writer.u8(static_cast<std::uint8_t>(observation.freshness));
}

Result<TelemetryObservation> read_observation(Reader& reader) {
  TelemetryObservation observation;
  Result<ObservationId> id = read_counter<ObservationIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  observation.id = id.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  observation.pdu = pdu.value();
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  observation.branch = branch.value();
  Result<PduGeneration> pdu_generation = read_counter<PduGenerationTag>(reader);
  if (!pdu_generation.ok()) {
    return pdu_generation.status();
  }
  observation.pdu_generation = pdu_generation.value();
  Result<BranchGeneration> branch_generation = read_counter<BranchGenerationTag>(reader);
  if (!branch_generation.ok()) {
    return branch_generation.status();
  }
  observation.branch_generation = branch_generation.value();
  Result<SourceId> source = read_id<SourceIdTag>(reader);
  if (!source.ok()) {
    return source.status();
  }
  observation.source = source.value();
  Result<SequenceNumber> sequence = read_counter<SequenceNumberTag>(reader);
  if (!sequence.ok()) {
    return sequence.status();
  }
  observation.sequence = sequence.value();
  Result<Instant> taken = read_instant(reader);
  if (!taken.ok()) {
    return taken.status();
  }
  observation.taken_at = taken.value();
  Result<Instant> received = read_instant(reader);
  if (!received.ok()) {
    return received.status();
  }
  observation.received_at = received.value();
  Result<LogicalTick> accepted = read_counter<LogicalTickTag>(reader);
  if (!accepted.ok()) {
    return accepted.status();
  }
  observation.accepted_tick = accepted.value();
  Result<std::uint8_t> quality = reader.u8();
  if (!quality.ok()) {
    return quality.status();
  }
  const Status quality_range = check_range(
      quality.value(), static_cast<std::uint64_t>(EvidenceQuality::unknown), "evidence quality");
  if (!quality_range.ok()) {
    return quality_range;
  }
  observation.quality = static_cast<EvidenceQuality>(quality.value());
  Result<std::uint8_t> condition = reader.u8();
  if (!condition.ok()) {
    return condition.status();
  }
  const Status condition_range = check_range(
      condition.value(), static_cast<std::uint64_t>(BranchCondition::unknown), "branch condition");
  if (!condition_range.ok()) {
    return condition_range;
  }
  observation.condition = static_cast<BranchCondition>(condition.value());
  Result<CurrentSample> current = read_sample<Current>(reader);
  if (!current.ok()) {
    return current.status();
  }
  observation.current = current.value();
  Result<VoltageSample> voltage = read_sample<Voltage>(reader);
  if (!voltage.ok()) {
    return voltage.status();
  }
  observation.voltage = voltage.value();
  Result<PowerSample> power = read_sample<Power>(reader);
  if (!power.ok()) {
    return power.status();
  }
  observation.power = power.value();
  Result<std::uint8_t> freshness = reader.u8();
  if (!freshness.ok()) {
    return freshness.status();
  }
  const Status freshness_range = check_range(
      freshness.value(), static_cast<std::uint64_t>(FreshnessState::unknown), "freshness state");
  if (!freshness_range.ok()) {
    return freshness_range;
  }
  observation.freshness = static_cast<FreshnessState>(freshness.value());
  return observation;
}

void write_grant(Writer& writer, const PermissionGrant& grant) {
  write_id(writer, grant.id);
  write_id(writer, grant.issuer);
  write_counter(writer, grant.epoch);
  write_id(writer, grant.pdu);
  write_id(writer, grant.branch);
  write_counter(writer, grant.pdu_generation);
  write_counter(writer, grant.branch_generation);
  writer.u16(grant.actions);
  write_counter(writer, grant.issued_at);
  write_counter(writer, grant.not_after);
  writer.boolean(grant.revoked);
  write_counter(writer, grant.revoked_at);
}

Result<PermissionGrant> read_grant(Reader& reader) {
  PermissionGrant grant;
  Result<AuthorityId> id = read_id<AuthorityIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  grant.id = id.value();
  Result<IssuerId> issuer = read_id<IssuerIdTag>(reader);
  if (!issuer.ok()) {
    return issuer.status();
  }
  grant.issuer = issuer.value();
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  grant.epoch = epoch.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  grant.pdu = pdu.value();
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  grant.branch = branch.value();
  Result<PduGeneration> pdu_generation = read_counter<PduGenerationTag>(reader);
  if (!pdu_generation.ok()) {
    return pdu_generation.status();
  }
  grant.pdu_generation = pdu_generation.value();
  Result<BranchGeneration> branch_generation = read_counter<BranchGenerationTag>(reader);
  if (!branch_generation.ok()) {
    return branch_generation.status();
  }
  grant.branch_generation = branch_generation.value();
  Result<std::uint16_t> actions = reader.u16();
  if (!actions.ok()) {
    return actions.status();
  }
  grant.actions = actions.value();
  Result<LogicalTick> issued = read_counter<LogicalTickTag>(reader);
  if (!issued.ok()) {
    return issued.status();
  }
  grant.issued_at = issued.value();
  Result<LogicalTick> not_after = read_counter<LogicalTickTag>(reader);
  if (!not_after.ok()) {
    return not_after.status();
  }
  grant.not_after = not_after.value();
  Result<bool> revoked = reader.boolean();
  if (!revoked.ok()) {
    return revoked.status();
  }
  grant.revoked = revoked.value();
  Result<LogicalTick> revoked_at = read_counter<LogicalTickTag>(reader);
  if (!revoked_at.ok()) {
    return revoked_at.status();
  }
  grant.revoked_at = revoked_at.value();
  return grant;
}


void write_override(Writer& writer, const MaintenanceOverride& value) {
  write_id(writer, value.id);
  write_id(writer, value.issuer);
  write_counter(writer, value.epoch);
  write_id(writer, value.pdu);
  write_id(writer, value.branch);
  write_counter(writer, value.pdu_generation);
  write_counter(writer, value.branch_generation);
  write_counter(writer, value.issued_at);
  write_counter(writer, value.not_after);
  writer.boolean(value.revoked);
}

Result<MaintenanceOverride> read_override(Reader& reader) {
  MaintenanceOverride value;
  Result<AuthorityId> id = read_id<AuthorityIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  value.id = id.value();
  Result<IssuerId> issuer = read_id<IssuerIdTag>(reader);
  if (!issuer.ok()) {
    return issuer.status();
  }
  value.issuer = issuer.value();
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  value.epoch = epoch.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  value.pdu = pdu.value();
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  value.branch = branch.value();
  Result<PduGeneration> pdu_generation = read_counter<PduGenerationTag>(reader);
  if (!pdu_generation.ok()) {
    return pdu_generation.status();
  }
  value.pdu_generation = pdu_generation.value();
  Result<BranchGeneration> branch_generation = read_counter<BranchGenerationTag>(reader);
  if (!branch_generation.ok()) {
    return branch_generation.status();
  }
  value.branch_generation = branch_generation.value();
  Result<LogicalTick> issued = read_counter<LogicalTickTag>(reader);
  if (!issued.ok()) {
    return issued.status();
  }
  value.issued_at = issued.value();
  Result<LogicalTick> not_after = read_counter<LogicalTickTag>(reader);
  if (!not_after.ok()) {
    return not_after.status();
  }
  value.not_after = not_after.value();
  Result<bool> revoked = reader.boolean();
  if (!revoked.ok()) {
    return revoked.status();
  }
  value.revoked = revoked.value();
  return value;
}

void write_interlock_record(Writer& writer, const InterlockRecord& record) {
  write_id(writer, record.declaration.id);
  write_id(writer, record.declaration.pdu);
  write_id(writer, record.declaration.branch);
  writer.u8(static_cast<std::uint8_t>(record.declaration.klass));
  write_counter(writer, record.declaration.declared_at);
  write_counter(writer, record.declaration.epoch);
  writer.boolean(record.has_status);
  write_id(writer, record.status.id);
  writer.u8(static_cast<std::uint8_t>(record.status.state));
  write_counter(writer, record.status.epoch);
  write_counter(writer, record.status.updated_at);
  write_id(writer, record.status.clearance);
}

Result<InterlockRecord> read_interlock_record(Reader& reader) {
  InterlockRecord record;
  Result<InterlockId> id = read_id<InterlockIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  record.declaration.id = id.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  record.declaration.pdu = pdu.value();
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  record.declaration.branch = branch.value();
  Result<std::uint8_t> klass = reader.u8();
  if (!klass.ok()) {
    return klass.status();
  }
  const Status klass_range = check_range(
      klass.value(), static_cast<std::uint64_t>(ObligationClass::advisory), "obligation class");
  if (!klass_range.ok()) {
    return klass_range;
  }
  record.declaration.klass = static_cast<ObligationClass>(klass.value());
  Result<LogicalTick> declared = read_counter<LogicalTickTag>(reader);
  if (!declared.ok()) {
    return declared.status();
  }
  record.declaration.declared_at = declared.value();
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  record.declaration.epoch = epoch.value();
  Result<bool> has_status = reader.boolean();
  if (!has_status.ok()) {
    return has_status.status();
  }
  record.has_status = has_status.value();
  Result<InterlockId> status_id = read_id<InterlockIdTag>(reader);
  if (!status_id.ok()) {
    return status_id.status();
  }
  record.status.id = status_id.value();
  Result<std::uint8_t> state = reader.u8();
  if (!state.ok()) {
    return state.status();
  }
  const Status state_range = check_range(
      state.value(), static_cast<std::uint64_t>(InterlockState::unknown), "interlock state");
  if (!state_range.ok()) {
    return state_range;
  }
  record.status.state = static_cast<InterlockState>(state.value());
  Result<AuthorityEpoch> status_epoch = read_counter<AuthorityEpochTag>(reader);
  if (!status_epoch.ok()) {
    return status_epoch.status();
  }
  record.status.epoch = status_epoch.value();
  Result<LogicalTick> updated = read_counter<LogicalTickTag>(reader);
  if (!updated.ok()) {
    return updated.status();
  }
  record.status.updated_at = updated.value();
  Result<AuthorityId> clearance = read_id<AuthorityIdTag>(reader);
  if (!clearance.ok()) {
    return clearance.status();
  }
  record.status.clearance = clearance.value();
  return record;
}

void write_authorization(Writer& writer, const ActuationAuthorization& authorization) {
  write_counter(writer, authorization.attempt());
  write_counter(writer, authorization.epoch());
  write_id(writer, authorization.pdu());
  write_id(writer, authorization.branch());
  write_counter(writer, authorization.pdu_generation());
  write_counter(writer, authorization.branch_generation());
  write_counter(writer, authorization.revision());
  write_counter(writer, authorization.issued_at());
  writer.u64(authorization.request_digest().value());
  writer.u32(authorization.validated());
  writer.boolean(authorization.maintenance_override());
}

Result<ActuationAuthorization> read_authorization(Reader& reader) {
  ActuationAuthorization authorization;
  Result<AttemptId> attempt = read_counter<AttemptIdTag>(reader);
  if (!attempt.ok()) {
    return attempt.status();
  }
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  Result<PduGeneration> pdu_generation = read_counter<PduGenerationTag>(reader);
  if (!pdu_generation.ok()) {
    return pdu_generation.status();
  }
  Result<BranchGeneration> branch_generation = read_counter<BranchGenerationTag>(reader);
  if (!branch_generation.ok()) {
    return branch_generation.status();
  }
  Result<StateRevision> revision = read_counter<StateRevisionTag>(reader);
  if (!revision.ok()) {
    return revision.status();
  }
  Result<LogicalTick> issued = read_counter<LogicalTickTag>(reader);
  if (!issued.ok()) {
    return issued.status();
  }
  Result<std::uint64_t> digest = reader.u64();
  if (!digest.ok()) {
    return digest.status();
  }
  Result<std::uint32_t> validated = reader.u32();
  if (!validated.ok()) {
    return validated.status();
  }
  Result<bool> override_used = reader.boolean();
  if (!override_used.ok()) {
    return override_used.status();
  }
  ActuationAccess::assign(authorization, attempt.value(), epoch.value(), pdu.value(),
                          branch.value(), pdu_generation.value(), branch_generation.value(),
                          revision.value(), issued.value(), Digest64::from(digest.value()),
                          validated.value(), override_used.value());
  return authorization;
}


void write_attempt(Writer& writer, const AttemptRecord& attempt) {
  write_counter(writer, attempt.id);
  write_id(writer, attempt.key);
  writer.u64(attempt.request_digest.value());
  writer.boolean(attempt.replayed);
  write_id(writer, attempt.pdu);
  write_id(writer, attempt.branch);
  write_counter(writer, attempt.planned_pdu_generation);
  write_counter(writer, attempt.planned_branch_generation);
  write_counter(writer, attempt.planned_revision);
  write_counter(writer, attempt.epoch);
  writer.u8(static_cast<std::uint8_t>(attempt.intent));
  write_counter(writer, attempt.requested_at);
  write_counter(writer, attempt.issued_at);
  writer.u8(static_cast<std::uint8_t>(attempt.outcome));
  writer.u16(static_cast<std::uint16_t>(attempt.code));
  (void)writer.text(attempt.detail, kMaxAdapterDetailBytes);
  write_authorization(writer, attempt.authorization);
  writer.boolean(attempt.dispatched);
  write_counter(writer, attempt.adapter_sequence);
  writer.u8(static_cast<std::uint8_t>(attempt.disposition));
  writer.u8(static_cast<std::uint8_t>(attempt.effect));
  write_counter(writer, attempt.verifying_observation);
  write_counter(writer, attempt.verified_at);
  writer.boolean(attempt.applied_command);
  writer.boolean(attempt.maintenance_override_used);
}

Result<AttemptRecord> read_attempt(Reader& reader) {
  AttemptRecord attempt;
  Result<AttemptId> id = read_counter<AttemptIdTag>(reader);
  if (!id.ok()) {
    return id.status();
  }
  attempt.id = id.value();
  Result<IdempotencyKey> key = read_id<IdempotencyKeyTag>(reader);
  if (!key.ok()) {
    return key.status();
  }
  attempt.key = key.value();
  Result<std::uint64_t> digest = reader.u64();
  if (!digest.ok()) {
    return digest.status();
  }
  attempt.request_digest = Digest64::from(digest.value());
  Result<bool> replayed = reader.boolean();
  if (!replayed.ok()) {
    return replayed.status();
  }
  attempt.replayed = replayed.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  attempt.pdu = pdu.value();
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  attempt.branch = branch.value();
  Result<PduGeneration> planned_pdu_generation = read_counter<PduGenerationTag>(reader);
  if (!planned_pdu_generation.ok()) {
    return planned_pdu_generation.status();
  }
  attempt.planned_pdu_generation = planned_pdu_generation.value();
  Result<BranchGeneration> planned_branch_generation = read_counter<BranchGenerationTag>(reader);
  if (!planned_branch_generation.ok()) {
    return planned_branch_generation.status();
  }
  attempt.planned_branch_generation = planned_branch_generation.value();
  Result<StateRevision> planned_revision = read_counter<StateRevisionTag>(reader);
  if (!planned_revision.ok()) {
    return planned_revision.status();
  }
  attempt.planned_revision = planned_revision.value();
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  attempt.epoch = epoch.value();
  Result<std::uint8_t> intent = reader.u8();
  if (!intent.ok()) {
    return intent.status();
  }
  const Status intent_range = check_range(
      intent.value(), static_cast<std::uint64_t>(CommandIntent::de_energize), "command intent");
  if (!intent_range.ok()) {
    return intent_range;
  }
  attempt.intent = static_cast<CommandIntent>(intent.value());
  Result<LogicalTick> requested = read_counter<LogicalTickTag>(reader);
  if (!requested.ok()) {
    return requested.status();
  }
  attempt.requested_at = requested.value();
  Result<LogicalTick> issued = read_counter<LogicalTickTag>(reader);
  if (!issued.ok()) {
    return issued.status();
  }
  attempt.issued_at = issued.value();
  Result<std::uint8_t> outcome = reader.u8();
  if (!outcome.ok()) {
    return outcome.status();
  }
  const Status outcome_range = check_range(
      outcome.value(), static_cast<std::uint64_t>(AttemptOutcome::cancelled), "attempt outcome");
  if (!outcome_range.ok()) {
    return outcome_range;
  }
  attempt.outcome = static_cast<AttemptOutcome>(outcome.value());
  Result<std::uint16_t> code = reader.u16();
  if (!code.ok()) {
    return code.status();
  }
  StatusCode status_code = StatusCode::internal;
  if (!parse_status_code(to_token(static_cast<StatusCode>(code.value())), status_code)) {
    return Status::failure(StatusCode::store_malformed, "the stored status code is not recognized");
  }
  attempt.code = status_code;
  Result<std::string> detail = reader.text(kMaxAdapterDetailBytes);
  if (!detail.ok()) {
    return detail.status();
  }
  attempt.detail = detail.value();
  Result<ActuationAuthorization> authorization = read_authorization(reader);
  if (!authorization.ok()) {
    return authorization.status();
  }
  attempt.authorization = authorization.value();
  Result<bool> dispatched = reader.boolean();
  if (!dispatched.ok()) {
    return dispatched.status();
  }
  attempt.dispatched = dispatched.value();
  Result<AdapterSequence> adapter_sequence = read_counter<AdapterSequenceTag>(reader);
  if (!adapter_sequence.ok()) {
    return adapter_sequence.status();
  }
  attempt.adapter_sequence = adapter_sequence.value();
  Result<std::uint8_t> disposition = reader.u8();
  if (!disposition.ok()) {
    return disposition.status();
  }
  const Status disposition_range = check_range(
      disposition.value(), static_cast<std::uint64_t>(AdapterDisposition::fault),
      "adapter disposition");
  if (!disposition_range.ok()) {
    return disposition_range;
  }
  attempt.disposition = static_cast<AdapterDisposition>(disposition.value());
  Result<std::uint8_t> effect = reader.u8();
  if (!effect.ok()) {
    return effect.status();
  }
  const Status effect_range = check_range(
      effect.value(), static_cast<std::uint64_t>(EffectState::unknown), "effect state");
  if (!effect_range.ok()) {
    return effect_range;
  }
  attempt.effect = static_cast<EffectState>(effect.value());
  Result<ObservationId> verifying = read_counter<ObservationIdTag>(reader);
  if (!verifying.ok()) {
    return verifying.status();
  }
  attempt.verifying_observation = verifying.value();
  Result<LogicalTick> verified_at = read_counter<LogicalTickTag>(reader);
  if (!verified_at.ok()) {
    return verified_at.status();
  }
  attempt.verified_at = verified_at.value();
  Result<bool> applied = reader.boolean();
  if (!applied.ok()) {
    return applied.status();
  }
  attempt.applied_command = applied.value();
  Result<bool> override_used = reader.boolean();
  if (!override_used.ok()) {
    return override_used.status();
  }
  attempt.maintenance_override_used = override_used.value();
  return attempt;
}

void write_audit(Writer& writer, const AuditEntry& entry) {
  write_counter(writer, entry.sequence);
  writer.u8(static_cast<std::uint8_t>(entry.kind));
  write_counter(writer, entry.tick);
  write_instant(writer, entry.wall);
  write_id(writer, entry.pdu);
  write_id(writer, entry.branch);
  write_counter(writer, entry.attempt);
  write_counter(writer, entry.observation);
  writer.u16(static_cast<std::uint16_t>(entry.code));
  (void)writer.text(entry.detail, kMaxAuditDetailBytes);
}

Result<AuditEntry> read_audit(Reader& reader) {
  AuditEntry entry;
  Result<SequenceNumber> sequence = read_counter<SequenceNumberTag>(reader);
  if (!sequence.ok()) {
    return sequence.status();
  }
  entry.sequence = sequence.value();
  Result<std::uint8_t> kind = reader.u8();
  if (!kind.ok()) {
    return kind.status();
  }
  const Status kind_range = check_range(
      kind.value(), static_cast<std::uint64_t>(AuditKind::recovery_adopted), "audit kind");
  if (!kind_range.ok()) {
    return kind_range;
  }
  entry.kind = static_cast<AuditKind>(kind.value());
  Result<LogicalTick> tick = read_counter<LogicalTickTag>(reader);
  if (!tick.ok()) {
    return tick.status();
  }
  entry.tick = tick.value();
  Result<Instant> wall = read_instant(reader);
  if (!wall.ok()) {
    return wall.status();
  }
  entry.wall = wall.value();
  Result<PduId> pdu = read_id<PduIdTag>(reader);
  if (!pdu.ok()) {
    return pdu.status();
  }
  entry.pdu = pdu.value();
  Result<BranchId> branch = read_id<BranchIdTag>(reader);
  if (!branch.ok()) {
    return branch.status();
  }
  entry.branch = branch.value();
  Result<AttemptId> attempt = read_counter<AttemptIdTag>(reader);
  if (!attempt.ok()) {
    return attempt.status();
  }
  entry.attempt = attempt.value();
  Result<ObservationId> observation = read_counter<ObservationIdTag>(reader);
  if (!observation.ok()) {
    return observation.status();
  }
  entry.observation = observation.value();
  Result<std::uint16_t> code = reader.u16();
  if (!code.ok()) {
    return code.status();
  }
  StatusCode status_code = StatusCode::internal;
  if (!parse_status_code(to_token(static_cast<StatusCode>(code.value())), status_code)) {
    return Status::failure(StatusCode::store_malformed, "the stored status code is not recognized");
  }
  entry.code = status_code;
  Result<std::string> detail = reader.text(kMaxAuditDetailBytes);
  if (!detail.ok()) {
    return detail.status();
  }
  entry.detail = detail.value();
  return entry;
}

void write_branch_state(Writer& writer, const BranchState& state) {
  writer.u8(static_cast<std::uint8_t>(state.lifecycle));
  write_counter(writer, state.revision);
  write_condition_sample(writer, state.commanded.condition);
  write_counter(writer, state.commanded.by_attempt);
  write_counter(writer, state.commanded.commanded_at);
  write_condition_sample(writer, state.verified.condition);
  write_counter(writer, state.verified.observation);
  write_counter(writer, state.verified.verified_at);
  write_counter(writer, state.verified.by_attempt);
  write_counter(writer, state.last_attempt);
  writer.boolean(state.unresolved_attempt);
  write_counter(writer, state.unresolved_since);
}

Result<BranchState> read_branch_state(Reader& reader) {
  BranchState state;
  Result<std::uint8_t> lifecycle = reader.u8();
  if (!lifecycle.ok()) {
    return lifecycle.status();
  }
  const Status range = check_range(lifecycle.value(),
                                   static_cast<std::uint64_t>(LifecycleState::retired),
                                   "lifecycle state");
  if (!range.ok()) {
    return range;
  }
  state.lifecycle = static_cast<LifecycleState>(lifecycle.value());
  Result<StateRevision> revision = read_counter<StateRevisionTag>(reader);
  if (!revision.ok()) {
    return revision.status();
  }
  state.revision = revision.value();
  Result<Sample<BranchCondition>> commanded = read_condition_sample(reader);
  if (!commanded.ok()) {
    return commanded.status();
  }
  state.commanded.condition = commanded.value();
  Result<AttemptId> by_attempt = read_counter<AttemptIdTag>(reader);
  if (!by_attempt.ok()) {
    return by_attempt.status();
  }
  state.commanded.by_attempt = by_attempt.value();
  Result<LogicalTick> commanded_at = read_counter<LogicalTickTag>(reader);
  if (!commanded_at.ok()) {
    return commanded_at.status();
  }
  state.commanded.commanded_at = commanded_at.value();
  Result<Sample<BranchCondition>> verified = read_condition_sample(reader);
  if (!verified.ok()) {
    return verified.status();
  }
  state.verified.condition = verified.value();
  Result<ObservationId> observation = read_counter<ObservationIdTag>(reader);
  if (!observation.ok()) {
    return observation.status();
  }
  state.verified.observation = observation.value();
  Result<LogicalTick> verified_at = read_counter<LogicalTickTag>(reader);
  if (!verified_at.ok()) {
    return verified_at.status();
  }
  state.verified.verified_at = verified_at.value();
  Result<AttemptId> verified_by = read_counter<AttemptIdTag>(reader);
  if (!verified_by.ok()) {
    return verified_by.status();
  }
  state.verified.by_attempt = verified_by.value();
  Result<AttemptId> last_attempt = read_counter<AttemptIdTag>(reader);
  if (!last_attempt.ok()) {
    return last_attempt.status();
  }
  state.last_attempt = last_attempt.value();
  Result<bool> unresolved = reader.boolean();
  if (!unresolved.ok()) {
    return unresolved.status();
  }
  state.unresolved_attempt = unresolved.value();
  Result<LogicalTick> unresolved_since = read_counter<LogicalTickTag>(reader);
  if (!unresolved_since.ok()) {
    return unresolved_since.status();
  }
  state.unresolved_since = unresolved_since.value();
  return state;
}

/// Saturating product, used only to derive an upper bound for a count check.
std::size_t bounded_product(std::size_t left, std::size_t right) noexcept {
  if (left == 0 || right == 0) {
    return 0;
  }
  if (left > static_cast<std::size_t>(-1) / right) {
    return static_cast<std::size_t>(-1);
  }
  return left * right;
}

Status read_observation_ring(Reader& reader, const ModelBounds& bounds, ObservationRing& ring) {
  Result<bool> has_current = reader.boolean();
  if (!has_current.ok()) {
    return has_current.status();
  }
  ring.has_current = has_current.value();
  if (ring.has_current) {
    Result<TelemetryObservation> current = read_observation(reader);
    if (!current.ok()) {
      return current.status();
    }
    ring.current = current.value();
  }
  Result<std::size_t> count = reader.count(bounds.max_observations_per_branch);
  if (!count.ok()) {
    return count.status();
  }
  // No reserve(): an untrusted count grows the vector only as real records are
  // decoded, so a hostile count fails on truncation instead of allocating.
  for (std::size_t index = 0; index < count.value(); ++index) {
    Result<TelemetryObservation> entry = read_observation(reader);
    if (!entry.ok()) {
      return entry.status();
    }
    ring.entries.push_back(entry.value());
  }
  return Status::success();
}

void write_observation_ring(Writer& writer, const ObservationRing& ring) {
  writer.boolean(ring.has_current);
  if (ring.has_current) {
    write_observation(writer, ring.current);
  }
  (void)writer.count(ring.entries.size(), 4096);
  for (const TelemetryObservation& entry : ring.entries) {
    write_observation(writer, entry);
  }
}

void write_model_state(Writer& writer, const ModelState& state, const ModelBounds& bounds) {
  write_counter(writer, state.authority_epoch);
  write_counter(writer, state.current_tick);
  write_instant(writer, state.wall);
  write_counter(writer, state.next_attempt);
  write_counter(writer, state.next_observation);
  write_counter(writer, state.next_adapter_sequence);
  write_counter(writer, state.next_audit_sequence);
  writer.u64(state.audit_dropped);
  writer.u64(state.open_count);
  write_counter(writer, state.last_incarnation);

  (void)writer.count(state.pdus.size(), bounds.max_pdus);
  for (const PduRecord& record : state.pdus) {
    write_pdu_definition(writer, record.definition);
    write_pdu_state(writer, record.state);
  }

  const std::size_t max_branches = bounded_product(bounds.max_pdus, bounds.max_branches_per_pdu);
  (void)writer.count(state.branches.size(), max_branches);
  for (const BranchRecord& record : state.branches) {
    write_branch_definition(writer, record.definition);
    write_branch_state(writer, record.state);
    write_observation_ring(writer, record.observations);
  }

  (void)writer.count(state.grants.size(), bounds.max_grants);
  for (const GrantRecord& record : state.grants) {
    write_grant(writer, record.grant);
  }

  (void)writer.count(state.overrides.size(), bounds.max_overrides);
  for (const OverrideRecord& record : state.overrides) {
    write_override(writer, record.value);
  }

  const std::size_t max_interlocks =
      bounded_product(max_branches, bounds.max_required_interlocks_per_branch);
  (void)writer.count(state.interlocks.size(), max_interlocks);
  for (const InterlockRecord& record : state.interlocks) {
    write_interlock_record(writer, record);
  }

  (void)writer.count(state.attempts.size(), bounds.max_attempt_journal);
  for (const AttemptRecord& record : state.attempts) {
    write_attempt(writer, record);
  }

  (void)writer.count(state.idempotency.size(), bounds.max_idempotency_window);
  for (const IdempotencyRecord& record : state.idempotency) {
    write_id(writer, record.key);
    writer.u64(record.request_digest.value());
    write_counter(writer, record.attempt);
  }

  (void)writer.count(state.audit.size(), bounds.max_audit_entries);
  for (const AuditEntry& entry : state.audit) {
    write_audit(writer, entry);
  }
}

Status read_model_state(Reader& reader, const ModelBounds& bounds, ModelState& state) {
  Result<AuthorityEpoch> epoch = read_counter<AuthorityEpochTag>(reader);
  if (!epoch.ok()) {
    return epoch.status();
  }
  state.authority_epoch = epoch.value();
  Result<LogicalTick> tick = read_counter<LogicalTickTag>(reader);
  if (!tick.ok()) {
    return tick.status();
  }
  state.current_tick = tick.value();
  Result<Instant> wall = read_instant(reader);
  if (!wall.ok()) {
    return wall.status();
  }
  state.wall = wall.value();
  Result<AttemptId> next_attempt = read_counter<AttemptIdTag>(reader);
  if (!next_attempt.ok()) {
    return next_attempt.status();
  }
  state.next_attempt = next_attempt.value();
  Result<ObservationId> next_observation = read_counter<ObservationIdTag>(reader);
  if (!next_observation.ok()) {
    return next_observation.status();
  }
  state.next_observation = next_observation.value();
  Result<AdapterSequence> next_sequence = read_counter<AdapterSequenceTag>(reader);
  if (!next_sequence.ok()) {
    return next_sequence.status();
  }
  state.next_adapter_sequence = next_sequence.value();
  Result<SequenceNumber> next_audit = read_counter<SequenceNumberTag>(reader);
  if (!next_audit.ok()) {
    return next_audit.status();
  }
  state.next_audit_sequence = next_audit.value();
  Result<std::uint64_t> dropped = reader.u64();
  if (!dropped.ok()) {
    return dropped.status();
  }
  state.audit_dropped = dropped.value();
  Result<std::uint64_t> open_count = reader.u64();
  if (!open_count.ok()) {
    return open_count.status();
  }
  state.open_count = open_count.value();
  Result<Incarnation> incarnation = read_counter<IncarnationTag>(reader);
  if (!incarnation.ok()) {
    return incarnation.status();
  }
  state.last_incarnation = incarnation.value();

  Result<std::size_t> pdu_count = reader.count(bounds.max_pdus);
  if (!pdu_count.ok()) {
    return pdu_count.status();
  }
  for (std::size_t index = 0; index < pdu_count.value(); ++index) {
    PduRecord record;
    Result<PduDefinition> definition = read_pdu_definition(reader);
    if (!definition.ok()) {
      return definition.status();
    }
    record.definition = definition.value();
    Result<PduState> pdu_state = read_pdu_state(reader);
    if (!pdu_state.ok()) {
      return pdu_state.status();
    }
    record.state = pdu_state.value();
    state.pdus.push_back(std::move(record));
  }

  const std::size_t max_branches = bounded_product(bounds.max_pdus, bounds.max_branches_per_pdu);
  Result<std::size_t> branch_count = reader.count(max_branches);
  if (!branch_count.ok()) {
    return branch_count.status();
  }
  for (std::size_t index = 0; index < branch_count.value(); ++index) {
    BranchRecord record;
    const Status definition = read_branch_definition(reader, bounds, record.definition);
    if (!definition.ok()) {
      return definition;
    }
    Result<BranchState> branch_state = read_branch_state(reader);
    if (!branch_state.ok()) {
      return branch_state.status();
    }
    record.state = branch_state.value();
    const Status ring = read_observation_ring(reader, bounds, record.observations);
    if (!ring.ok()) {
      return ring;
    }
    state.branches.push_back(std::move(record));
  }

  Result<std::size_t> grant_count = reader.count(bounds.max_grants);
  if (!grant_count.ok()) {
    return grant_count.status();
  }
  for (std::size_t index = 0; index < grant_count.value(); ++index) {
    GrantRecord record;
    Result<PermissionGrant> grant = read_grant(reader);
    if (!grant.ok()) {
      return grant.status();
    }
    record.grant = grant.value();
    state.grants.push_back(std::move(record));
  }

  Result<std::size_t> override_count = reader.count(bounds.max_overrides);
  if (!override_count.ok()) {
    return override_count.status();
  }
  for (std::size_t index = 0; index < override_count.value(); ++index) {
    OverrideRecord record;
    Result<MaintenanceOverride> value = read_override(reader);
    if (!value.ok()) {
      return value.status();
    }
    record.value = value.value();
    state.overrides.push_back(std::move(record));
  }

  const std::size_t max_interlocks =
      bounded_product(max_branches, bounds.max_required_interlocks_per_branch);
  Result<std::size_t> interlock_count = reader.count(max_interlocks);
  if (!interlock_count.ok()) {
    return interlock_count.status();
  }
  for (std::size_t index = 0; index < interlock_count.value(); ++index) {
    Result<InterlockRecord> record = read_interlock_record(reader);
    if (!record.ok()) {
      return record.status();
    }
    state.interlocks.push_back(record.value());
  }

  Result<std::size_t> attempt_count = reader.count(bounds.max_attempt_journal);
  if (!attempt_count.ok()) {
    return attempt_count.status();
  }
  for (std::size_t index = 0; index < attempt_count.value(); ++index) {
    Result<AttemptRecord> record = read_attempt(reader);
    if (!record.ok()) {
      return record.status();
    }
    state.attempts.push_back(record.value());
  }

  Result<std::size_t> idempotency_count = reader.count(bounds.max_idempotency_window);
  if (!idempotency_count.ok()) {
    return idempotency_count.status();
  }
  for (std::size_t index = 0; index < idempotency_count.value(); ++index) {
    IdempotencyRecord record;
    Result<IdempotencyKey> key = read_id<IdempotencyKeyTag>(reader);
    if (!key.ok()) {
      return key.status();
    }
    record.key = key.value();
    Result<std::uint64_t> digest = reader.u64();
    if (!digest.ok()) {
      return digest.status();
    }
    record.request_digest = Digest64::from(digest.value());
    Result<AttemptId> attempt = read_counter<AttemptIdTag>(reader);
    if (!attempt.ok()) {
      return attempt.status();
    }
    record.attempt = attempt.value();
    state.idempotency.push_back(std::move(record));
  }

  Result<std::size_t> audit_count = reader.count(bounds.max_audit_entries);
  if (!audit_count.ok()) {
    return audit_count.status();
  }
  for (std::size_t index = 0; index < audit_count.value(); ++index) {
    Result<AuditEntry> entry = read_audit(reader);
    if (!entry.ok()) {
      return entry.status();
    }
    state.audit.push_back(entry.value());
  }
  return Status::success();
}

/// Referential integrity of a decoded state.
///
/// A store is adopted whole or not at all, and "whole" includes being internally
/// consistent: a branch whose PDU is missing, an attempt whose branch is missing,
/// or a grant that points at nothing is not a state this runtime could ever have
/// produced, so it is refused rather than loaded and repaired.
Status check_references(const ModelState& state) {
  for (const BranchRecord& branch : state.branches) {
    bool found = false;
    for (const PduRecord& pdu : state.pdus) {
      if (pdu.definition.id == branch.definition.pdu) {
        found = true;
        break;
      }
    }
    if (!found) {
      return Status::failure(StatusCode::store_malformed,
                             "a stored branch refers to a PDU that is not in the store");
    }
  }
  const auto branch_exists = [&state](const PduId& pdu, const BranchId& branch) {
    for (const BranchRecord& record : state.branches) {
      if (record.definition.id == branch && record.definition.pdu == pdu) {
        return true;
      }
    }
    return false;
  };
  for (const GrantRecord& record : state.grants) {
    if (!branch_exists(record.grant.pdu, record.grant.branch)) {
      return Status::failure(StatusCode::store_malformed,
                             "a stored grant refers to a branch that is not in the store");
    }
  }
  for (const OverrideRecord& record : state.overrides) {
    if (!branch_exists(record.value.pdu, record.value.branch)) {
      return Status::failure(StatusCode::store_malformed,
                             "a stored maintenance override refers to a branch that is not in "
                             "the store");
    }
  }
  for (const InterlockRecord& record : state.interlocks) {
    if (!branch_exists(record.declaration.pdu, record.declaration.branch)) {
      return Status::failure(StatusCode::store_malformed,
                             "a stored interlock refers to a branch that is not in the store");
    }
  }
  for (const AttemptRecord& record : state.attempts) {
    if (!branch_exists(record.pdu, record.branch)) {
      return Status::failure(StatusCode::store_malformed,
                             "a stored attempt refers to a branch that is not in the store");
    }
  }
  for (const IdempotencyRecord& record : state.idempotency) {
    bool found = false;
    for (const AttemptRecord& attempt : state.attempts) {
      if (attempt.id == record.attempt) {
        found = true;
        break;
      }
    }
    if (!found) {
      return Status::failure(StatusCode::store_malformed,
                             "a stored idempotency entry refers to an attempt that is not in the "
                             "journal");
    }
  }
  for (const BranchRecord& branch : state.branches) {
    for (const TelemetryObservation& entry : branch.observations.entries) {
      if (entry.branch != branch.definition.id || entry.pdu != branch.definition.pdu) {
        return Status::failure(StatusCode::store_malformed,
                               "a stored observation is filed under another branch");
      }
    }
    if (branch.observations.has_current &&
        (branch.observations.current.branch != branch.definition.id ||
         branch.observations.current.pdu != branch.definition.pdu)) {
      return Status::failure(StatusCode::store_malformed,
                             "the stored current observation is filed under another branch");
    }
  }
  return Status::success();
}

// --- canonical text --------------------------------------------------------

void append_u64(std::string& out, std::uint64_t value) {
  out.append(std::to_string(value));
  out.push_back(' ');
}

template <typename Tag>
void append_id(std::string& out, const Identifier<Tag>& id) {
  out.append(id.empty() ? std::string_view("-") : std::string_view(id.value()));
  out.push_back(' ');
}

template <typename Tag>
void append_counter(std::string& out, const Counter<Tag>& counter) {
  append_u64(out, counter.value());
}

void append_bool(std::string& out, bool value) {
  out.append(value ? "1" : "0");
  out.push_back(' ');
}

void append_raw(std::string& out, std::string_view text) {
  out.append(text);
  out.push_back(' ');
}

void append_escaped(std::string& out, std::string_view text) {
  static constexpr char kDigits[] = "0123456789ABCDEF";
  out.push_back('"');
  for (const char value : text) {
    const auto code = static_cast<unsigned char>(value);
    if (value == '"' || value == '\\') {
      out.push_back('\\');
      out.push_back(value);
    } else if (code < 0x20 || code > 0x7E) {
      out.append("\\x");
      out.push_back(kDigits[(code >> 4) & 0xF]);
      out.push_back(kDigits[code & 0xF]);
    } else {
      out.push_back(value);
    }
  }
  out.push_back('"');
  out.push_back(' ');
}

template <typename Q>
void append_quantity_sample(std::string& out, const Sample<Q>& sample) {
  append_raw(out, to_token(sample.state()));
  if (sample.has_value()) {
    append_u64(out, static_cast<std::uint64_t>(sample.value().raw()));
  }
}

void append_condition_sample(std::string& out, const Sample<BranchCondition>& sample) {
  append_raw(out, to_token(sample.state()));
  if (sample.has_value()) {
    append_raw(out, to_token(sample.value()));
  }
}

void append_instant(std::string& out, const Instant& instant) {
  append_raw(out, to_token(instant.domain));
  append_u64(out, instant.tick.value());
  append_u64(out, static_cast<std::uint64_t>(instant.nanoseconds));
}

void append_limits(std::string& out, const BranchLimits& limits) {
  append_quantity_sample(out, limits.continuous_current);
  append_quantity_sample(out, limits.peak_current);
  append_quantity_sample(out, limits.power);
  append_id(out, limits.provenance.issuer);
  append_id(out, limits.provenance.authority);
  append_counter(out, limits.provenance.epoch);
  append_counter(out, limits.provenance.stated_at);
  append_counter(out, limits.provenance.not_after);
  append_counter(out, limits.revision);
}

void append_observation(std::string& out, const TelemetryObservation& observation) {
  append_counter(out, observation.id);
  append_id(out, observation.pdu);
  append_id(out, observation.branch);
  append_counter(out, observation.pdu_generation);
  append_counter(out, observation.branch_generation);
  append_id(out, observation.source);
  append_counter(out, observation.sequence);
  append_instant(out, observation.taken_at);
  // received_at is a caller-supplied wall or monotonic instant and is
  // deliberately not part of canonical content.
  append_counter(out, observation.accepted_tick);
  append_raw(out, to_token(observation.quality));
  append_raw(out, to_token(observation.condition));
  append_quantity_sample(out, observation.current);
  append_quantity_sample(out, observation.voltage);
  append_quantity_sample(out, observation.power);
  // The stored freshness label is deliberately excluded. It is derived from the
  // facts above plus the instant it is asked about, and it is rewritten to
  // `recovered` when state comes back off disk; including it would make the
  // digest of one logical state differ between a live engine and a reopened one.
}

/// True for audit entries that describe the runtime instance rather than the
/// controlled system. Opening and closing an engine is not a change to the
/// model, so those entries are excluded from the canonical state: otherwise the
/// digest of one logical state would differ between a live engine and a
/// reopened one.
bool is_runtime_audit(AuditKind kind) {
  return kind == AuditKind::engine_opened || kind == AuditKind::engine_reopened ||
         kind == AuditKind::engine_closed;
}

void append_audit(std::string& out, const AuditEntry& entry) {
  append_counter(out, entry.sequence);
  append_raw(out, to_token(entry.kind));
  append_counter(out, entry.tick);
  // The wall-clock instant on an audit entry is intentional audit content, not
  // model state, and is excluded so that two logically identical engines digest
  // identically.
  append_id(out, entry.pdu);
  append_id(out, entry.branch);
  append_counter(out, entry.attempt);
  append_counter(out, entry.observation);
  append_raw(out, to_token(entry.code));
  append_escaped(out, entry.detail);
}

}  // namespace

Result<PayloadHeader> decode_payload_header(const std::uint8_t* data, std::size_t size) {
  if (size < kEnvelopeBytes) {
    return Status::failure(StatusCode::store_truncated, "the payload is shorter than its envelope");
  }
  Reader reader(data, size);
  Result<std::string_view> magic = reader.raw(store_payload_magic.size());
  if (!magic.ok()) {
    return magic.status();
  }
  if (magic.value() != store_payload_magic) {
    return Status::failure(StatusCode::store_malformed, "the payload magic does not match");
  }
  Result<std::uint32_t> version = reader.u32();
  if (!version.ok()) {
    return version.status();
  }
  if (version.value() != store_format_version) {
    return Status::failure(StatusCode::store_version_unsupported,
                           "the payload declares format version " +
                               std::to_string(version.value()) + " and this build writes " +
                               std::to_string(store_format_version));
  }
  Result<std::uint64_t> generation = reader.u64();
  if (!generation.ok()) {
    return generation.status();
  }
  Result<std::uint64_t> incarnation = reader.u64();
  if (!incarnation.ok()) {
    return incarnation.status();
  }
  Result<std::uint32_t> body_bytes = reader.u32();
  if (!body_bytes.ok()) {
    return body_bytes.status();
  }
  const auto declared = static_cast<std::uint64_t>(body_bytes.value()) + kEnvelopeBytes;
  if (declared != size) {
    return Status::failure(StatusCode::store_malformed,
                           "the payload declares " + std::to_string(body_bytes.value()) +
                               " body bytes but the record holds " +
                               std::to_string(size - kEnvelopeBytes));
  }
  if (body_bytes.value() > store_max_payload_bytes) {
    return Status::failure(StatusCode::store_oversized,
                           "the payload is larger than this build accepts");
  }
  PayloadHeader header;
  header.generation = StoreGeneration::from(generation.value());
  header.incarnation = Incarnation::from(incarnation.value());
  header.body_bytes = body_bytes.value();
  return header;
}

Result<std::vector<std::uint8_t>> encode_state(const ModelState& state, const ModelBounds& bounds) {
  Writer body;
  write_model_state(body, state, bounds);
  if (body.size() > store_max_payload_bytes) {
    return Status::failure(StatusCode::store_oversized,
                           "the encoded state is " + std::to_string(body.size()) +
                               " bytes and the format allows " +
                               std::to_string(store_max_payload_bytes));
  }
  Writer writer;
  writer.raw(store_payload_magic.data(), store_payload_magic.size());
  writer.u32(store_format_version);
  writer.u64(state.generation.value());
  writer.u64(state.last_incarnation.value());
  writer.u32(static_cast<std::uint32_t>(body.size()));
  writer.raw(body.bytes().data(), body.bytes().size());
  return writer.bytes();
}

Result<ModelState> decode_state(const std::uint8_t* data, std::size_t size,
                                const ModelBounds& bounds) {
  Result<PayloadHeader> header = decode_payload_header(data, size);
  if (!header.ok()) {
    return header.status();
  }
  Reader reader(data + kEnvelopeBytes, size - kEnvelopeBytes);
  ModelState state;
  state.generation = header.value().generation;
  const Status decoded = read_model_state(reader, bounds, state);
  if (!decoded.ok()) {
    return decoded;
  }
  const Status trailing = reader.expect_end();
  if (!trailing.ok()) {
    return trailing;
  }
  const Status references = check_references(state);
  if (!references.ok()) {
    return references;
  }
  // Everything that comes off durable storage is recovered evidence. It stays
  // stale until a fresh reading revalidates it, whatever its freshness was when
  // it was written.
  for (BranchRecord& branch : state.branches) {
    branch.observations.current.freshness = FreshnessState::recovered;
    for (TelemetryObservation& entry : branch.observations.entries) {
      entry.freshness = FreshnessState::recovered;
    }
  }
  return state;
}

std::string canonical_text(const ModelState& state) {
  std::string out;
  out.reserve(4096);
  append_raw(out, "pdu-control-canonical");
  append_u64(out, 1);
  out.push_back('\n');

  out.append("tick ");
  append_counter(out, state.current_tick);
  out.append("\nepoch ");
  append_counter(out, state.authority_epoch);
  out.append("\n");

  out.append("pdus ");
  append_u64(out, state.pdus.size());
  out.push_back('\n');
  for (const PduRecord& record : state.pdus) {
    out.append("pdu ");
    append_id(out, record.definition.id);
    append_counter(out, record.definition.generation);
    append_raw(out, to_token(record.definition.lifecycle));
    append_escaped(out, record.definition.label);
    append_id(out, record.definition.owner);
    append_id(out, record.definition.zone);
    append_counter(out, record.definition.registered_at);
    append_raw(out, to_token(record.state.lifecycle));
    append_counter(out, record.state.revision);
    out.push_back('\n');
  }

  out.append("branches ");
  append_u64(out, state.branches.size());
  out.push_back('\n');
  for (const BranchRecord& record : state.branches) {
    out.append("branch ");
    append_id(out, record.definition.pdu);
    append_id(out, record.definition.id);
    append_counter(out, record.definition.generation);
    append_raw(out, to_token(record.definition.lifecycle));
    append_escaped(out, record.definition.label);
    append_raw(out, to_token(record.state.lifecycle));
    append_counter(out, record.state.revision);
    append_condition_sample(out, record.state.commanded.condition);
    append_counter(out, record.state.commanded.by_attempt);
    append_counter(out, record.state.commanded.commanded_at);
    append_condition_sample(out, record.state.verified.condition);
    append_counter(out, record.state.verified.observation);
    append_counter(out, record.state.verified.verified_at);
    append_counter(out, record.state.verified.by_attempt);
    append_counter(out, record.state.last_attempt);
    append_bool(out, record.state.unresolved_attempt);
    append_counter(out, record.state.unresolved_since);
    out.push_back('\n');

    out.append("limits ");
    append_limits(out, record.definition.limits);
    out.push_back('\n');

    out.append("required ");
    append_u64(out, record.definition.required_interlocks.size());
    for (const InterlockId& id : record.definition.required_interlocks) {
      append_id(out, id);
    }
    out.push_back('\n');

    out.append("observations ");
    append_bool(out, record.observations.has_current);
    append_u64(out, record.observations.entries.size());
    out.push_back('\n');
    if (record.observations.has_current) {
      out.append("current ");
      append_observation(out, record.observations.current);
      out.push_back('\n');
    }
    for (const TelemetryObservation& entry : record.observations.entries) {
      out.append("observation ");
      append_observation(out, entry);
      out.push_back('\n');
    }
  }

  out.append("grants ");
  append_u64(out, state.grants.size());
  out.push_back('\n');
  for (const GrantRecord& record : state.grants) {
    out.append("grant ");
    append_id(out, record.grant.id);
    append_id(out, record.grant.issuer);
    append_counter(out, record.grant.epoch);
    append_id(out, record.grant.pdu);
    append_id(out, record.grant.branch);
    append_counter(out, record.grant.pdu_generation);
    append_counter(out, record.grant.branch_generation);
    append_raw(out, to_token(record.grant.actions));
    append_counter(out, record.grant.issued_at);
    append_counter(out, record.grant.not_after);
    append_bool(out, record.grant.revoked);
    append_counter(out, record.grant.revoked_at);
    out.push_back('\n');
  }

  out.append("overrides ");
  append_u64(out, state.overrides.size());
  out.push_back('\n');
  for (const OverrideRecord& record : state.overrides) {
    out.append("override ");
    append_id(out, record.value.id);
    append_id(out, record.value.issuer);
    append_counter(out, record.value.epoch);
    append_id(out, record.value.pdu);
    append_id(out, record.value.branch);
    append_counter(out, record.value.pdu_generation);
    append_counter(out, record.value.branch_generation);
    append_counter(out, record.value.issued_at);
    append_counter(out, record.value.not_after);
    append_bool(out, record.value.revoked);
    out.push_back('\n');
  }

  out.append("interlocks ");
  append_u64(out, state.interlocks.size());
  out.push_back('\n');
  for (const InterlockRecord& record : state.interlocks) {
    out.append("interlock ");
    append_id(out, record.declaration.id);
    append_id(out, record.declaration.pdu);
    append_id(out, record.declaration.branch);
    append_raw(out, to_token(record.declaration.klass));
    append_counter(out, record.declaration.declared_at);
    append_counter(out, record.declaration.epoch);
    append_bool(out, record.has_status);
    append_raw(out, to_token(record.status.state));
    append_counter(out, record.status.epoch);
    append_counter(out, record.status.updated_at);
    append_id(out, record.status.clearance);
    out.push_back('\n');
  }

  out.append("attempts ");
  append_u64(out, state.attempts.size());
  out.push_back('\n');
  for (const AttemptRecord& record : state.attempts) {
    out.append("attempt ");
    append_counter(out, record.id);
    append_id(out, record.key);
    append_u64(out, record.request_digest.value());
    append_id(out, record.pdu);
    append_id(out, record.branch);
    append_counter(out, record.planned_pdu_generation);
    append_counter(out, record.planned_branch_generation);
    append_counter(out, record.planned_revision);
    append_counter(out, record.epoch);
    append_raw(out, to_token(record.intent));
    append_counter(out, record.requested_at);
    append_counter(out, record.issued_at);
    append_raw(out, to_token(record.outcome));
    append_raw(out, to_token(record.code));
    append_counter(out, record.authorization.attempt());
    append_u64(out, record.authorization.validated());
    append_bool(out, record.authorization.maintenance_override());
    append_bool(out, record.dispatched);
    append_counter(out, record.adapter_sequence);
    append_raw(out, to_token(record.disposition));
    append_raw(out, to_token(record.effect));
    append_counter(out, record.verifying_observation);
    append_counter(out, record.verified_at);
    append_bool(out, record.applied_command);
    append_bool(out, record.maintenance_override_used);
    out.push_back('\n');
  }

  out.append("idempotency ");
  append_u64(out, state.idempotency.size());
  out.push_back('\n');
  for (const IdempotencyRecord& record : state.idempotency) {
    out.append("idem ");
    append_id(out, record.key);
    append_u64(out, record.request_digest.value());
    append_counter(out, record.attempt);
    out.push_back('\n');
  }

  std::size_t canonical_audit = 0;
  for (const AuditEntry& entry : state.audit) {
    if (!is_runtime_audit(entry.kind)) {
      canonical_audit += 1;
    }
  }
  out.append("audit ");
  append_u64(out, canonical_audit);
  out.push_back('\n');
  for (const AuditEntry& entry : state.audit) {
    if (is_runtime_audit(entry.kind)) {
      continue;
    }
    out.append("a ");
    append_audit(out, entry);
    out.push_back('\n');
  }
  return out;
}

}  // namespace pdu_control::detail

