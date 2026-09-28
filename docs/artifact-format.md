# PDU Control durable artifact format

This document describes the bytes that `pdu_control` writes to disk. It is the
contract the store reader and writer implement, and it is what the adversarial
tests attack.

## Scope

The format stores the **authoritative model state** of one engine: identities,
generations, revisions, lifecycle, limits, permissions, interlocks, telemetry
observations, the attempt journal, the idempotency window, the audit ring, the
adopted authority epoch, and the store generation. It does not store adapter
configuration, credentials, endpoints, or anything a vendor supplied.

Everything in the file is derived from the runtime's own state. The library never
reads the system clock, so no timestamp in this file comes from the host.

## File layout

    offset 0                      head record A   (256 bytes)
    offset 256                    head record B   (256 bytes)
    offset 512                    payload slot 0  (64-byte header, then payload)
    offset 512 + stride           payload slot 1
    stride = 4096 + 4 MiB

    file size = 512 + 2 * stride

A store is created at its full size and is never a different size afterwards. A
file whose length is not exactly the format length is refused: shorter is
`store_truncated`, longer is `store_oversized`.

## Encoding rules

* All integers are little-endian, written byte by byte. No structure is written
  with its in-memory representation, so compiler padding and host endianness
  cannot leak into the file.
* Text is a 32-bit little-endian byte length followed by that many bytes.
  Identities are at most 96 bytes, labels 160 bytes, audit detail 192 bytes, and
  adapter detail 256 bytes.
* Enumerators are written as their underlying integer and range-checked on read.
  An out-of-range value is `store_malformed`, never an out-of-range enum.
* Collection counts are 32-bit and are checked against the bound that applies to
  them **before** anything is allocated for them. The decoder never reserves
  memory based on an untrusted count: elements are appended as they are
  successfully decoded, so a hostile count fails on truncation.
* Every field is written and every field is read. A decode that does not consume
  the payload exactly fails with `store_malformed`.

## Head record (256 bytes)

| offset | size | field |
|--------|------|-------|
| 0      | 8    | magic `PDUCHD01` |
| 8      | 4    | format version (little-endian) |
| 12     | 4    | flags, reserved, zero |
| 16     | 8    | serial: strictly increasing per publication |
| 24     | 8    | store generation |
| 32     | 8    | incarnation of the writer that published it |
| 40     | 8    | authority epoch at publication |
| 48     | 4    | payload slot index (0 or 1) |
| 52     | 4    | payload length in bytes |
| 56     | 4    | CRC-32C of the payload |
| 60     | 4    | reserved, zero |
| 64     | 8    | engine open count at publication |
| 72     | 8    | non-cryptographic digest of the payload |
| 80     | 4    | CRC-32C over bytes 0..79 of this record |
| 84     | 172  | zero padding |

A head record is valid only when its magic matches, its format version is this
build's, and its CRC matches. A record that fails any of those is *invalid*, not
an error: that is what a head write torn by a crash looks like.

## Payload slot header (64 bytes)

| offset | size | field |
|--------|------|-------|
| 0      | 8    | magic `PDUCSL01` |
| 8      | 4    | format version |
| 12     | 4    | flags, reserved, zero |
| 16     | 8    | store generation |
| 24     | 8    | incarnation |
| 32     | 8    | authority epoch |
| 40     | 4    | payload length |
| 44     | 4    | CRC-32C of the payload |
| 48     | 4    | CRC-32C over bytes 0..47 of this header |
| 52     | 12   | zero padding |

## Payload envelope

| offset | size | field |
|--------|------|-------|
| 0      | 8    | magic `PDUCTLP1` |
| 8      | 4    | format version |
| 12     | 8    | store generation |
| 20     | 8    | incarnation |
| 28     | 4    | body length |
| 32     | n    | body |

The envelope repeats the generation and incarnation of the slot header so that a
slot from another generation cannot be spliced in without the mismatch being
visible. The body is the encoded model, described by `src/detail/serialization.cpp`.

## Publication protocol

    plan      build the state to publish
    reserve   allocate the next store generation
    stage     write the payload into the slot the head does not reference
    flush     flush the staged bytes to the device
    verify    read the staged slot back and verify magic, version, length, CRC
    publish   write the head record that names the verified slot, and flush
    retire    the previous slot becomes residue; the next publication overwrites it

**The commit point is the head write that follows the verified payload, flushed
to the device.** Nothing before it is authoritative, and a payload that has been
written but not committed is invisible after a restart.

Head records alternate between slots A and B, so a crash while one head record is
being written leaves the other one intact.

## Recovery rules

On open:

1. The two head records are read. Each is valid or invalid by magic, version, and
   CRC. No repair is attempted.
2. If neither is valid, the store is refused with `store_malformed`.
3. The valid head with the **largest serial** is adopted. Its payload slot is read
   and verified in full; if the slot does not verify, the store is refused. The
   other head is never consulted as a fallback after a valid head was chosen.
4. The decoded state must satisfy referential integrity: every branch names a PDU
   in the store, every grant, override, interlock, and attempt names a branch in
   the store, every idempotency entry names an attempt in the journal, and every
   observation is filed under its own branch.
5. Every observation read from disk has its freshness set to `recovered`. It
   stays stale until a fresh reading revalidates it, whatever its freshness was
   when it was written.

Generations are never stitched together. A generation is adopted whole or not at
all.

### Rollback

If the newest head record is present but unreadable, the previous whole
generation is adopted. That case is indistinguishable from a head write torn by a
crash, so it is treated as a legitimate recovery rather than as corruption — and
it *is* a rollback.

A caller that requires monotonic authority arms the fence:
`EngineOptions::min_store_generation`. Opening a store whose adopted generation
is below the fence fails with `rollback_detected`. The engine never lowers the
fence and never rewrites it.

## Fencing a stale writer

A store is held by one writer at a time through an operating-system lock on the
sidecar file `<store>.lock` (Windows: a handle opened with no sharing; POSIX:
`flock(LOCK_EX)`). A second opener is refused with `busy`, and the operating
system releases the lock when the holder dies, so a killed writer leaves no
residue.

Every publication re-reads the head first and refuses with `busy` when the head
on disk is not the one this writer last committed. That is defence in depth
against a writer whose lock was lost or bypassed: it cannot overwrite a
generation it never saw, and the refusal is counted in
`StoreAudit::fenced_writes`.

Every open allocates a new incarnation (the previous one plus one), so a writer
that was thought to be alive can always be told apart from its successor. The
incarnation is recorded in the slot header, the payload envelope, and the head
record, and it is part of the audit surface.

## Integrity, not authentication

CRC-32C detects accident, truncation, and partial writes. It is not a signature:
an adversary who can rewrite the file can rewrite its checksums. The format
protects against corruption, not against an attacker with write access to the
store. Nothing in the file is secret.

## Path trust model

A store path is validated before anything is opened:

1. Lexical checks on the original text, before any normalization, so that
   normalization cannot erase the evidence of an attack: an embedded NUL is
   refused; a path longer than 4096 bytes is refused; any component equal to
   `.` or `..` is refused; a final component that is a reserved device name
   (`CON`, `NUL`, `COM1`, …) is refused.
2. Normalization to an absolute path.
3. Filesystem checks on the normalized path: the final component must not be a
   directory, and must not be a symbolic link, junction, or other reparse point.

Malformed UTF-8 is refused rather than replaced. Every refusal is
`path_invalid` with a message naming the check that fired. Opening or creating a
store creates any missing parent directory, after the path itself has passed
every check.

## Versioning

The format version is written in the head record, the slot header, and the
payload envelope, and all three must agree with the build. A store written by
another version is refused with `store_version_unsupported`; it is never
reinterpreted. There is no automatic migration: a future version that changes the
layout must write a new version number and the reader must refuse the old one
rather than guess.
