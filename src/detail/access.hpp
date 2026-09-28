#pragma once

// Internal accessor for \c ActuationAuthorization.
//
// The type's members are private and the only friends are the engine and this
// accessor, so an adapter cannot mint an authorization and cannot widen the
// precondition mask of one it was given. The durable decoder needs the same
// ability as the engine, which is why this exists at all.

#include <utility>

#include "pdu_control/adapter.hpp"

namespace pdu_control::detail {

struct ActuationAccess {
  static void assign(ActuationAuthorization& target, AttemptId attempt, AuthorityEpoch epoch,
                     PduId pdu, BranchId branch, PduGeneration pdu_generation,
                     BranchGeneration branch_generation, StateRevision revision,
                     LogicalTick issued_at, Digest64 request_digest,
                     PreconditionMask validated, bool maintenance_override) {
    target.attempt_ = attempt;
    target.epoch_ = epoch;
    target.pdu_ = std::move(pdu);
    target.branch_ = std::move(branch);
    target.pdu_generation_ = pdu_generation;
    target.branch_generation_ = branch_generation;
    target.revision_ = revision;
    target.issued_at_ = issued_at;
    target.request_digest_ = request_digest;
    target.validated_ = validated;
    target.maintenance_override_ = maintenance_override;
  }
};

}  // namespace pdu_control::detail
