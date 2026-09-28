#include "detail/store_file.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "detail/crc32c.hpp"
#include "pdu_control/version.hpp"

namespace pdu_control::detail {
namespace {

// Fixed-layout record helpers. The store records are written field by field in
// little-endian order rather than through the general codec, because their
// layout is part of the documented format and must not drift with the codec.

void put_u32(std::uint8_t* buffer, std::size_t offset, std::uint32_t value) noexcept {
  for (std::size_t index = 0; index < 4; ++index) {
    buffer[offset + index] = static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFU);
  }
}

void put_u64(std::uint8_t* buffer, std::size_t offset, std::uint64_t value) noexcept {
  for (std::size_t index = 0; index < 8; ++index) {
    buffer[offset + index] = static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFULL);
  }
}

std::uint32_t get_u32(const std::uint8_t* buffer, std::size_t offset) noexcept {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(buffer[offset + index]) << (index * 8);
  }
  return value;
}

std::uint64_t get_u64(const std::uint8_t* buffer, std::size_t offset) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(buffer[offset + index]) << (index * 8);
  }
  return value;
}

constexpr std::size_t kHeadCrcOffset = 80;
constexpr std::size_t kHeadCrcCovered = 80;
constexpr std::size_t kSlotCrcOffset = 48;
constexpr std::size_t kSlotCrcCovered = 48;

std::size_t head_offset(std::uint32_t index) noexcept {
  return static_cast<std::size_t>(index) * store_head_record_bytes;
}

std::size_t slot_offset(std::uint32_t index) noexcept {
  return store_head_bytes + static_cast<std::size_t>(index) * store_slot_stride;
}

void encode_head(std::uint8_t* buffer, const StoreHead& head) noexcept {
  std::memset(buffer, 0, store_head_record_bytes);
  std::memcpy(buffer, store_head_magic.data(), store_head_magic.size());
  put_u32(buffer, 8, store_format_version);
  put_u32(buffer, 12, 0);
  put_u64(buffer, 16, head.serial);
  put_u64(buffer, 24, head.generation.value());
  put_u64(buffer, 32, head.incarnation.value());
  put_u64(buffer, 40, head.epoch.value());
  put_u32(buffer, 48, head.slot);
  put_u32(buffer, 52, head.payload_bytes);
  put_u32(buffer, 56, head.payload_crc);
  put_u32(buffer, 60, 0);
  put_u64(buffer, 64, head.open_count);
  put_u64(buffer, 72, head.payload_digest.value());
  put_u32(buffer, kHeadCrcOffset, crc32c(buffer, kHeadCrcCovered));
}

void encode_slot_header(std::uint8_t* buffer, const StoreHead& head) noexcept {
  std::memset(buffer, 0, store_slot_header_bytes);
  std::memcpy(buffer, store_slot_magic.data(), store_slot_magic.size());
  put_u32(buffer, 8, store_format_version);
  put_u32(buffer, 12, 0);
  put_u64(buffer, 16, head.generation.value());
  put_u64(buffer, 24, head.incarnation.value());
  put_u64(buffer, 32, head.epoch.value());
  put_u32(buffer, 40, head.payload_bytes);
  put_u32(buffer, 44, head.payload_crc);
  put_u32(buffer, kSlotCrcOffset, crc32c(buffer, kSlotCrcCovered));
}

}  // namespace

StoreFile::~StoreFile() { (void)close(); }

StoreFile::StoreFile(StoreFile&& other) noexcept
    : data_(std::move(other.data_)),
      lock_(std::move(other.lock_)),
      state_(std::move(other.state_)),
      head_(other.head_),
      incarnation_(other.incarnation_),
      min_generation_(other.min_generation_),
      bounds_(other.bounds_),
      audit_(std::move(other.audit_)),
      read_only_(other.read_only_),
      next_head_slot_(other.next_head_slot_) {
  other.head_ = StoreHead{};
  other.next_head_slot_ = 0;
}

StoreFile& StoreFile::operator=(StoreFile&& other) noexcept {
  if (this != &other) {
    (void)close();
    data_ = std::move(other.data_);
    lock_ = std::move(other.lock_);
    state_ = std::move(other.state_);
    head_ = other.head_;
    incarnation_ = other.incarnation_;
    min_generation_ = other.min_generation_;
    bounds_ = other.bounds_;
    audit_ = std::move(other.audit_);
    read_only_ = other.read_only_;
    next_head_slot_ = other.next_head_slot_;
    other.head_ = StoreHead{};
    other.next_head_slot_ = 0;
  }
  return *this;
}

Result<StoreHead> StoreFile::read_head_slot(std::uint32_t head_slot) const {
  std::uint8_t buffer[store_head_record_bytes] = {};
  const Status read = data_.read_at(head_offset(head_slot), buffer, sizeof(buffer));
  if (!read.ok()) {
    return read;
  }
  StoreHead head;
  head.record_index = head_slot;
  if (std::memcmp(buffer, store_head_magic.data(), store_head_magic.size()) != 0) {
    return head;  // never written, or overwritten by something else
  }
  const std::uint32_t version = get_u32(buffer, 8);
  if (version != store_format_version) {
    return Status::failure(StatusCode::store_version_unsupported,
                           "the head record declares format version " + std::to_string(version) +
                               " and this build writes " + std::to_string(store_format_version));
  }
  const std::uint32_t stored_crc = get_u32(buffer, kHeadCrcOffset);
  if (stored_crc != crc32c(buffer, kHeadCrcCovered)) {
    return head;  // torn or corrupt: not valid, and not an error by itself
  }
  head.valid = true;
  head.serial = get_u64(buffer, 16);
  head.generation = StoreGeneration::from(get_u64(buffer, 24));
  head.incarnation = Incarnation::from(get_u64(buffer, 32));
  head.epoch = AuthorityEpoch::from(get_u64(buffer, 40));
  head.slot = get_u32(buffer, 48);
  head.payload_bytes = get_u32(buffer, 52);
  head.payload_crc = get_u32(buffer, 56);
  head.open_count = get_u64(buffer, 64);
  head.payload_digest = Digest64::from(get_u64(buffer, 72));
  if (head.slot > 1) {
    return Status::failure(StatusCode::store_malformed,
                           "a head record names payload slot " + std::to_string(head.slot) +
                               " and only slots 0 and 1 exist");
  }
  if (head.payload_bytes > store_max_payload_bytes) {
    return Status::failure(StatusCode::store_oversized,
                           "a head record declares " + std::to_string(head.payload_bytes) +
                               " payload bytes, above the format maximum");
  }
  return head;
}

Result<StoreHead> StoreFile::read_head() const {
  // A store that has never been published has no head record at all. That is
  // "nothing is committed yet", which is different from a head record that is
  // present but unreadable.
  Result<std::uint64_t> size = data_.size();
  if (!size.ok()) {
    return size.status();
  }
  if (size.value() < store_head_bytes) {
    return StoreHead{};
  }
  Result<StoreHead> first = read_head_slot(0);
  if (!first.ok()) {
    return first.status();
  }
  Result<StoreHead> second = read_head_slot(1);
  if (!second.ok()) {
    return second.status();
  }
  StoreHead best;
  for (const StoreHead* candidate : {&first.value(), &second.value()}) {
    if (!candidate->valid) {
      continue;
    }
    if (!best.valid || candidate->serial > best.serial) {
      best = *candidate;
    }
  }
  return best;
}

Result<ModelState> StoreFile::load_slot(const StoreHead& head) const {
  std::uint8_t header[store_slot_header_bytes] = {};
  const std::size_t offset = slot_offset(head.slot);
  Status status = data_.read_at(offset, header, sizeof(header));
  if (!status.ok()) {
    return status;
  }
  if (std::memcmp(header, store_slot_magic.data(), store_slot_magic.size()) != 0) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload slot does not carry the slot magic");
  }
  if (get_u32(header, 8) != store_format_version) {
    return Status::failure(StatusCode::store_version_unsupported,
                           "the committed payload slot declares another format version");
  }
  if (get_u32(header, kSlotCrcOffset) != crc32c(header, kSlotCrcCovered)) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload slot header fails its checksum");
  }
  if (StoreGeneration::from(get_u64(header, 16)) != head.generation) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload slot belongs to another generation");
  }
  if (Incarnation::from(get_u64(header, 24)) != head.incarnation) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload slot belongs to another incarnation");
  }
  const std::uint32_t payload_bytes = get_u32(header, 40);
  if (payload_bytes != head.payload_bytes) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload slot declares a different payload length than "
                           "its head record");
  }
  std::vector<std::uint8_t> payload(payload_bytes);
  if (payload_bytes > 0) {
    status = data_.read_at(offset + store_slot_header_bytes, payload.data(), payload.size());
    if (!status.ok()) {
      return status;
    }
  }
  if (crc32c(payload.data(), payload.size()) != head.payload_crc) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload fails its checksum");
  }
  Result<PayloadHeader> envelope = decode_payload_header(payload.data(), payload.size());
  if (!envelope.ok()) {
    return envelope.status();
  }
  if (envelope.value().generation != head.generation ||
      envelope.value().incarnation != head.incarnation) {
    return Status::failure(StatusCode::store_malformed,
                           "the committed payload envelope disagrees with its head record");
  }
  return decode_state(payload.data(), payload.size(), bounds_);
}

Result<StoreFile> StoreFile::open(const std::string& path, OpenMode mode, const ModelBounds& bounds,
                                  bool read_only, StoreGeneration min_generation) {
  StoreFile store;
  store.bounds_ = bounds;
  store.min_generation_ = min_generation;
  store.read_only_ = read_only || mode == OpenMode::read_only;
  store.audit_.durable = true;
  store.audit_.path = path;
  store.audit_.format_version = store_format_version;
  store.audit_.read_only = store.read_only_;
  store.audit_.min_accepted_generation = min_generation;
  store.audit_.rollback_fence_armed = min_generation.is_set();

  // The path itself was validated by the caller; creating the directory that
  // holds the store is part of creating the store, and doing it here means every
  // entry point behaves the same way.
  const Status directory = ensure_parent_directory(path);
  if (!directory.ok()) {
    return directory;
  }

  // Write authority is taken before anything else is inspected, so two openers
  // can never both believe they own the store.
  const std::string lock_path = path + std::string(store_lock_suffix);
  FileOpenOptions lock_options;
  lock_options.create_if_missing = true;
  lock_options.exclusive = true;
  Result<File> lock = File::open(lock_path, FileAccess::read_write, lock_options);
  if (!lock.ok()) {
    return lock.status();
  }
  store.lock_ = std::move(lock.value());
  store.audit_.exclusively_locked = true;

  const bool exists = path_exists(path);
  switch (mode) {
    case OpenMode::create_new:
      if (exists) {
        return Status::failure(StatusCode::duplicate_identity,
                               "a store already exists at this path and create_new was requested");
      }
      break;
    case OpenMode::open_existing:
    case OpenMode::read_only:
      if (!exists) {
        return Status::failure(StatusCode::not_found, "no store exists at this path");
      }
      break;
    case OpenMode::open_or_create:
      break;
  }

  FileOpenOptions data_options;
  data_options.exclusive = false;
  if (store.read_only_) {
    data_options.must_exist = true;
  } else if (exists) {
    data_options.must_exist = true;
  } else {
    data_options.create_if_missing = true;
  }
  Result<File> data = File::open(path, store.read_only_ ? FileAccess::read_only : FileAccess::read_write,
                                 data_options);
  if (!data.ok()) {
    return data.status();
  }
  store.data_ = std::move(data.value());

  Result<std::uint64_t> size = store.data_.size();
  if (!size.ok()) {
    return size.status();
  }

  if (size.value() == 0) {
    if (store.read_only_) {
      return Status::failure(StatusCode::store_malformed,
                             "the store is empty; there is no committed state to read");
    }
    // A brand new store is sized to the format and published immediately, so
    // that a crash one instruction later still leaves a well-formed store
    // behind, and so that every subsequent publication writes inside a file
    // whose length is exactly what the format declares.
    const Status sized = store.data_.resize(store_file_bytes);
    if (!sized.ok()) {
      return sized;
    }
    store.state_ = ModelState{};
    store.state_.open_count = 1;
    store.incarnation_ = Incarnation::from(1);
    store.next_head_slot_ = 0;
    const Status published = store.publish(store.state_);
    if (!published.ok()) {
      return published;
    }
    store.audit_.generation = store.head_.generation;
    store.audit_.published_generation = store.head_.generation;
    store.audit_.incarnation = store.incarnation_;
    store.audit_.stored_incarnation = store.head_.incarnation;
    store.audit_.open_count = store.state_.open_count;
    return store;
  }

  if (size.value() < store_file_bytes) {
    return Status::failure(StatusCode::store_truncated,
                           "the store is " + std::to_string(size.value()) +
                               " bytes and a well-formed store is " +
                               std::to_string(store_file_bytes) + " bytes");
  }
  if (size.value() > store_file_bytes) {
    return Status::failure(StatusCode::store_oversized,
                           "the store is " + std::to_string(size.value()) +
                               " bytes and a well-formed store is " +
                               std::to_string(store_file_bytes) + " bytes");
  }

  Result<StoreHead> first = store.read_head_slot(0);
  if (!first.ok()) {
    store.audit_.crc_mismatches += 1;
    store.audit_.rejected_open_attempts += 1;
    return first.status();
  }
  Result<StoreHead> second = store.read_head_slot(1);
  if (!second.ok()) {
    store.audit_.crc_mismatches += 1;
    store.audit_.rejected_open_attempts += 1;
    return second.status();
  }
  store.audit_.head_records_valid = static_cast<std::uint32_t>(first.value().valid) +
                                    static_cast<std::uint32_t>(second.value().valid);
  StoreHead best;
  for (const StoreHead* candidate : {&first.value(), &second.value()}) {
    if (candidate->valid && (!best.valid || candidate->serial > best.serial)) {
      best = *candidate;
    }
  }
  if (!best.valid) {
    store.audit_.rejected_open_attempts += 1;
    return Status::failure(StatusCode::store_malformed,
                           "neither head record is valid; the store is not adopted");
  }
  Result<ModelState> loaded = store.load_slot(best);
  if (!loaded.ok()) {
    store.audit_.rejected_open_attempts += 1;
    if (loaded.code() == StatusCode::store_malformed) {
      store.audit_.crc_mismatches += 1;
    }
    return loaded.status();
  }
  if (min_generation.is_set() && best.generation < min_generation) {
    store.audit_.rejected_open_attempts += 1;
    return Status::failure(StatusCode::rollback_detected,
                           "the store is committed at generation " +
                               std::to_string(best.generation.value()) +
                               " and the caller requires at least " +
                               std::to_string(min_generation.value()));
  }

  store.state_ = std::move(loaded.value());
  store.head_ = best;
  store.next_head_slot_ = 1 - best.record_index;
  store.audit_.head_slot_index = best.slot;
  store.audit_.generation = best.generation;
  store.audit_.published_generation = best.generation;
  store.audit_.stored_incarnation = best.incarnation;
  store.audit_.open_count = store.state_.open_count + 1;
  if (store.read_only_) {
    store.incarnation_ = best.incarnation;
  } else {
    Result<Incarnation> next = best.incarnation.next();
    if (!next.ok()) {
      return next.status();
    }
    store.incarnation_ = next.value();
    store.state_.open_count += 1;
  }
  store.audit_.incarnation = store.incarnation_;
  return store;
}

Status StoreFile::write_head(const StoreHead& head, std::uint32_t head_slot) {
  std::uint8_t buffer[store_head_record_bytes] = {};
  encode_head(buffer, head);
  const Status written = data_.write_at(head_offset(head_slot), buffer, sizeof(buffer));
  if (!written.ok()) {
    return written;
  }
  audit_.bytes_written += sizeof(buffer);
  audit_.head_writes += 1;
  return Status::success();
}

Status StoreFile::publish(const ModelState& state) {
  if (read_only_) {
    return Status::failure(StatusCode::store_locked,
                           "the store was opened read-only and refuses publication");
  }
  if (!data_.is_open()) {
    return Status::failure(StatusCode::store_io, "the store is not open");
  }

  // Fence: the head on disk must still be the one this writer last committed.
  // A different incarnation or generation means another process has advanced the
  // store, and this writer's view is stale.
  Result<StoreHead> current = read_head();
  if (!current.ok()) {
    return current.status();
  }
  if (current.value().valid) {
    const StoreHead& disk = current.value();
    // The comparison is against the head this writer last committed, not against
    // the incarnation it just allocated. A writer adopts the *previous*
    // incarnation when it opens and only stamps its own on the next publication,
    // so comparing against the new one would fence every writer immediately.
    const bool owns_head = head_.valid && disk.incarnation == head_.incarnation &&
                           disk.generation == head_.generation && disk.serial == head_.serial;
    if (!owns_head) {
      audit_.fenced_writes += 1;
      return Status::failure(StatusCode::busy,
                             "the store head was advanced by another writer; this writer is "
                             "fenced and must reopen");
    }
  }

  Result<StoreGeneration> next = head_.generation.next();
  if (!next.ok()) {
    return next.status();
  }

  ModelState staged = state;
  staged.generation = next.value();
  staged.last_incarnation = incarnation_;

  Result<std::vector<std::uint8_t>> encoded = encode_state(staged, bounds_);
  if (!encoded.ok()) {
    return encoded.status();
  }
  std::vector<std::uint8_t>& payload = encoded.value();
  if (payload.size() > store_max_payload_bytes) {
    return Status::failure(StatusCode::store_oversized,
                           "the state encodes to " + std::to_string(payload.size()) +
                               " bytes, above the format maximum");
  }

  StoreHead candidate;
  candidate.valid = true;
  candidate.serial = head_.serial + 1;
  candidate.generation = staged.generation;
  candidate.incarnation = incarnation_;
  candidate.epoch = staged.authority_epoch;
  candidate.slot = head_.valid ? (1U - head_.slot) : 0U;
  candidate.payload_bytes = static_cast<std::uint32_t>(payload.size());
  candidate.payload_crc = crc32c(payload.data(), payload.size());
  candidate.open_count = staged.open_count;
  DigestBuilder builder;
  builder.update(payload.data(), payload.size());
  candidate.payload_digest = builder.finish();

  std::uint8_t slot_header[store_slot_header_bytes] = {};
  encode_slot_header(slot_header, candidate);
  const std::size_t offset = slot_offset(candidate.slot);
  Status status = data_.write_at(offset, slot_header, sizeof(slot_header));
  if (!status.ok()) {
    return status;
  }
  audit_.bytes_written += sizeof(slot_header);
  if (!payload.empty()) {
    status = data_.write_at(offset + store_slot_header_bytes, payload.data(), payload.size());
    if (!status.ok()) {
      return status;
    }
    audit_.bytes_written += payload.size();
  }
  status = data_.flush();
  if (!status.ok()) {
    return status;
  }
  audit_.flushes += 1;
  audit_.slot_writes += 1;

  // Read back what was written and verify it before the head is allowed to name
  // it. The head write is the commit point, and nothing before it is trusted.
  std::vector<std::uint8_t> readback(store_slot_header_bytes + payload.size());
  status = data_.read_at(offset, readback.data(), readback.size());
  if (!status.ok()) {
    return status;
  }
  audit_.bytes_read += readback.size();
  if (std::memcmp(readback.data(), slot_header, store_slot_header_bytes) != 0) {
    return Status::failure(StatusCode::store_io,
                           "the staged slot header did not read back identically");
  }
  const std::uint8_t* readback_payload = readback.data() + store_slot_header_bytes;
  if (crc32c(readback_payload, payload.size()) != candidate.payload_crc) {
    return Status::failure(StatusCode::store_io,
                           "the staged payload did not read back with the same checksum");
  }
  if (payload.size() > 0 && std::memcmp(readback_payload, payload.data(), payload.size()) != 0) {
    return Status::failure(StatusCode::store_io, "the staged payload did not read back identically");
  }
  audit_.readback_verifications += 1;

  status = write_head(candidate, next_head_slot_);
  if (!status.ok()) {
    return status;
  }
  status = data_.flush();
  if (!status.ok()) {
    return status;
  }
  audit_.flushes += 1;

  next_head_slot_ = 1U - next_head_slot_;
  head_ = candidate;
  state_ = std::move(staged);
  audit_.publication_count += 1;
  audit_.generation = head_.generation;
  audit_.published_generation = head_.generation;
  audit_.incarnation = incarnation_;
  audit_.stored_incarnation = incarnation_;
  audit_.head_slot_index = head_.slot;
  audit_.last_published_digest = head_.payload_digest;
  audit_.open_count = state_.open_count;
  audit_.current_tick = state_.current_tick;
  audit_.authority_epoch = state_.authority_epoch;
  return Status::success();
}

Status StoreFile::close() {
  Status result = Status::success();
  if (data_.is_open()) {
    result = data_.close();
  }
  if (lock_.is_open()) {
    const Status released = lock_.close();
    if (result.ok()) {
      result = released;
    }
  }
  audit_.open = false;
  audit_.exclusively_locked = false;
  return result;
}

}  // namespace pdu_control::detail
