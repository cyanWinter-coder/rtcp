// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Default limits used by UnmarshalPartial for limit fields that are zero.
const (
	// DefaultPartialCompoundMaxPackets is the default maximum number of
	// subpackets UnmarshalPartial inspects.
	DefaultPartialCompoundMaxPackets = 256

	// DefaultPartialCompoundMaxTotalBytes is the default maximum number of
	// bytes a subpacket may reach, relative to the start of the datagram.
	DefaultPartialCompoundMaxTotalBytes = 1 << 20

	// DefaultPartialCompoundMaxPacketBytes is the default maximum size of a
	// single subpacket. It matches the largest size the RTCP length field can
	// describe: (0xFFFF+1) 32-bit words.
	DefaultPartialCompoundMaxPacketBytes = (0xFFFF + 1) * headerLength
)

// PartialCompoundLimits bounds the work performed by UnmarshalPartial.
//
// A zero field selects the corresponding DefaultPartialCompound... value, so
// the zero value always yields a bounded parse. A negative field disables that
// particular limit.
type PartialCompoundLimits struct {
	// MaxPackets is the maximum number of subpacket slots inspected. Corrupt
	// and unknown packets count toward the limit as well.
	MaxPackets int

	// MaxTotalBytes is the maximum number of datagram bytes covered by
	// inspected subpackets. Parsing stops before a subpacket that would extend
	// past this many bytes from the start of the datagram.
	MaxTotalBytes int

	// MaxPacketBytes is the maximum size of a single subpacket as declared by
	// its RTCP header.
	MaxPacketBytes int
}

// packetLimit returns the effective packet limit. The effective value is only
// ever positive or unbounded.
func (l PartialCompoundLimits) packetLimit() int {
	return effectivePartialLimit(l.MaxPackets, DefaultPartialCompoundMaxPackets)
}

// totalBytesLimit returns the effective total bytes limit. The effective value
// is only ever positive or unbounded.
func (l PartialCompoundLimits) totalBytesLimit() int {
	return effectivePartialLimit(l.MaxTotalBytes, DefaultPartialCompoundMaxTotalBytes)
}

// packetBytesLimit returns the effective per-packet limit. The effective value
// is only ever positive or unbounded.
func (l PartialCompoundLimits) packetBytesLimit() int {
	return effectivePartialLimit(l.MaxPacketBytes, DefaultPartialCompoundMaxPacketBytes)
}

func effectivePartialLimit(value, fallback int) int {
	switch {
	case value == 0:
		return fallback
	case value < 0:
		// A non-positive effective limit means unbounded.
		return 0
	default:
		return value
	}
}

// PartialCompoundEntry describes one RTCP subpacket slot found by
// UnmarshalPartial.
//
// Offset and Raw locate the packet in the input datagram. Raw is a read-only
// view into the input slice, never a copy, and its capacity is capped at its
// length so appending to it cannot overwrite the bytes that follow it.
type PartialCompoundEntry struct {
	// Index is the zero-based position of the slot in the datagram.
	Index int

	// Offset is the byte offset of the slot from the start of the datagram.
	Offset int

	// Length is the packet size in bytes as declared by the RTCP header. For
	// an incomplete trailing packet this is the declared size, which is larger
	// than len(Raw); Raw then holds every byte that is available. When fewer
	// than four bytes remain there is no header to read a declared size from,
	// and Length equals len(Raw).
	Length int

	// Type is the RTCP packet type from the header. It is only meaningful
	// once a full header was available.
	Type PacketType

	// Raw is the byte range occupied by the slot, including a partial tail.
	Raw []byte

	// Packet is the successfully decoded packet, or nil when Err is non-nil.
	// Unknown packet types decode as *RawPacket, matching Unmarshal; that
	// packet shares the datagram's backing array, exactly as Unmarshal's does.
	Packet Packet

	// Err is non-nil when this slot could not be decoded. It is always a
	// *PartialPacketError, which carries the index, offset and underlying
	// error.
	Err error
}

// PartialCompoundPacket is the result of a partial parse.
//
// Packets holds every complete, successfully decoded subpacket in order. It is
// a CompoundPacket, so the strict CompoundPacket.Validate rules apply unchanged
// to that subset. Corrupt and truncated slots never appear in Packets.
type PartialCompoundPacket struct {
	// Packets is the valid subset of the datagram.
	Packets CompoundPacket

	// Entries describes every subpacket slot that was inspected, in order. It
	// includes the valid packets, unknown packet types and corrupt slots.
	Entries []PartialCompoundEntry

	// Err aggregates every corrupt subpacket and the terminal stop condition.
	// It is nil when the whole datagram was cleanly consumed, and equals the
	// error returned by UnmarshalPartial. Use errors.Is and errors.As to
	// inspect it, or read the individual entries.
	Err error
}

// PartialPacketError reports a subpacket that could not be decoded.
//
// It is available through PartialCompoundEntry.Err and through the error
// returned by UnmarshalPartial. errors.Is matches ErrPartialCompoundCorrupt as
// well as the underlying stop reason, and errors.As can recover this value.
type PartialPacketError struct {
	// Index is the zero-based position of the slot in the datagram.
	Index int

	// Offset is the byte offset of the slot from the start of the datagram.
	Offset int

	// Length is the packet size declared by the RTCP header.
	Length int

	// Type is the RTCP packet type from the header.
	Type PacketType

	// Err is the underlying cause.
	Err error
}

// Error implements the error interface.
func (e *PartialPacketError) Error() string {
	return fmt.Sprintf("rtcp: subpacket %d at offset %d (length %d, type %d): %v",
		e.Index, e.Offset, e.Length, e.Type, e.Err)
}

// Unwrap reports ErrPartialCompoundCorrupt together with the underlying cause,
// so a truncated tail matches both ErrPartialCompoundCorrupt and
// ErrPartialCompoundTruncated.
func (e *PartialPacketError) Unwrap() []error {
	return []error{ErrPartialCompoundCorrupt, e.Err}
}

// PartialCompoundError reports why UnmarshalPartial stopped before the end of
// the input.
//
// It is available through PartialCompoundPacket.Err and through the error
// returned by UnmarshalPartial. errors.Is matches the relevant
// ErrPartialCompound... sentinel.
type PartialCompoundError struct {
	// Offset is the byte offset at which parsing stopped.
	Offset int

	// Length is the size declared by the offending subpacket's header, or the
	// number of remaining bytes when no full header was available.
	Length int

	// Limit is the configured limit that was exceeded, or zero when parsing
	// stopped because the final subpacket was incomplete.
	Limit int

	// Err is the underlying sentinel error.
	Err error
}

// Error implements the error interface.
func (e *PartialCompoundError) Error() string {
	return fmt.Sprintf("rtcp: partial compound stopped at offset %d (length %d, limit %d): %v",
		e.Offset, e.Length, e.Limit, e.Err)
}

// Unwrap returns the sentinel error describing the stop reason.
func (e *PartialCompoundError) Unwrap() error {
	return e.Err
}

// UnmarshalPartial decodes as much of rawData as it can without discarding the
// whole datagram when one subpacket is damaged.
//
// Subpackets are split strictly by the 32-bit word length declared in each
// RTCP header. A final subpacket whose declared length overruns the datagram is
// reported as truncated and is never reinterpreted as the start of another
// packet. A subpacket whose contents fail to decode is reported as corrupt and
// skipped by its declared length, so valid feedback that follows it is still
// recovered. If the length field itself is corrupt, the bytes it declares are
// still skipped verbatim; the parser does not guess at alternative header
// boundaries, so packets hidden inside a bogus length cannot be recovered.
//
// Unknown packet types are skipped safely by their declared length and decode
// as *RawPacket, exactly like Unmarshal. Their original byte range is preserved
// in PartialCompoundEntry.Raw.
//
// Unlike Unmarshal, UnmarshalPartial never modifies rawData and does not
// enforce CompoundPacket.Validate. The returned report is never nil and is
// populated even when the error is non-nil; the error aggregates every corrupt
// subpacket and the terminal stop condition. An empty datagram yields an empty
// report and a nil error.
//
// limits bounds the number of inspected packets, the total bytes inspected and
// the size of a single packet. As soon as a limit is exceeded parsing stops,
// no further entries are appended and no further packet is decoded. A zero
// field selects the corresponding DefaultPartialCompound... value; a negative
// field disables that limit.
func UnmarshalPartial(rawData []byte, limits PartialCompoundLimits) (*PartialCompoundPacket, error) {
	report := &PartialCompoundPacket{}
	var stop error

	offset := 0

	for offset < len(rawData) {
		if maxPackets := limits.packetLimit(); maxPackets > 0 && len(report.Entries) >= maxPackets {
			length, _ := declaredSubpacketLength(rawData, offset)
			stop = &PartialCompoundError{
				Offset: offset,
				Length: length,
				Limit:  maxPackets,
				Err:    ErrPartialCompoundTooManyPackets,
			}

			break
		}

		length, stopErr := partialSubpacketLength(rawData, offset, limits)
		if stopErr != nil {
			stop = stopErr
			if errors.Is(stopErr.Err, ErrPartialCompoundTruncated) {
				report.Entries = append(report.Entries, truncatedEntry(rawData, len(report.Entries), offset, length))
			}

			break
		}

		slot := rawData[offset : offset+length : offset+length]
		entry := partialEntry(slot, len(report.Entries), offset)
		report.Entries = append(report.Entries, entry)
		if entry.Packet != nil {
			report.Packets = append(report.Packets, entry.Packet)
		}

		offset += length
	}

	report.Err = report.aggregateError(stop)

	return report, report.Err
}

// declaredSubpacketLength reads the size declared by the header at offset. It
// reports false when fewer than four bytes remain, in which case it returns
// the number of remaining bytes.
func declaredSubpacketLength(rawData []byte, offset int) (int, bool) {
	if len(rawData)-offset < headerLength {
		return len(rawData) - offset, false
	}

	return (int(binary.BigEndian.Uint16(rawData[offset+2:])) + 1) * headerLength, true
}

// partialSubpacketLength inspects the header at offset and returns the
// declared packet length. When a limit is exceeded or the declared length
// overruns the datagram it returns the stop condition instead, with the
// declared length.
func partialSubpacketLength(rawData []byte, offset int, limits PartialCompoundLimits) (int, *PartialCompoundError) {
	length, complete := declaredSubpacketLength(rawData, offset)
	if !complete {
		// Never treat an incomplete tail as the start of another packet.
		return length, &PartialCompoundError{
			Offset: offset,
			Length: length,
			Err:    ErrPartialCompoundTruncated,
		}
	}

	if maxPacketBytes := limits.packetBytesLimit(); maxPacketBytes > 0 && length > maxPacketBytes {
		return length, &PartialCompoundError{
			Offset: offset,
			Length: length,
			Limit:  maxPacketBytes,
			Err:    ErrPartialCompoundPacketTooLarge,
		}
	}

	if maxTotalBytes := limits.totalBytesLimit(); maxTotalBytes > 0 && offset+length > maxTotalBytes {
		return length, &PartialCompoundError{
			Offset: offset,
			Length: length,
			Limit:  maxTotalBytes,
			Err:    ErrPartialCompoundTooManyBytes,
		}
	}

	if length > len(rawData)-offset {
		return length, &PartialCompoundError{
			Offset: offset,
			Length: length,
			Err:    ErrPartialCompoundTruncated,
		}
	}

	return length, nil
}

// partialEntry decodes a single complete subpacket slot, which may still be
// corrupt.
func partialEntry(slot []byte, index, offset int) PartialCompoundEntry {
	packet, _, err := unmarshal(slot)
	entry := PartialCompoundEntry{
		Index:  index,
		Offset: offset,
		Length: len(slot),
		Type:   PacketType(slot[1]),
		Raw:    slot,
	}
	if err != nil {
		entry.Err = &PartialPacketError{
			Index:  index,
			Offset: offset,
			Length: len(slot),
			Type:   entry.Type,
			Err:    err,
		}
	} else {
		entry.Packet = packet
	}

	return entry
}

// truncatedEntry describes an incomplete trailing subpacket.
func truncatedEntry(rawData []byte, index, offset, length int) PartialCompoundEntry {
	tail := rawData[offset:]
	entry := PartialCompoundEntry{
		Index:  index,
		Offset: offset,
		Length: length,
		Raw:    slices.Clip(tail),
	}
	if len(tail) >= headerLength {
		entry.Type = PacketType(tail[1])
	}
	entry.Err = &PartialPacketError{
		Index:  index,
		Offset: offset,
		Length: length,
		Type:   entry.Type,
		Err:    ErrPartialCompoundTruncated,
	}

	return entry
}

// aggregateError joins every subpacket failure and the terminal stop error.
func (p *PartialCompoundPacket) aggregateError(stop error) error {
	var errs []error

	for i := range p.Entries {
		if p.Entries[i].Err != nil {
			errs = append(errs, p.Entries[i].Err)
		}
	}
	if stop != nil {
		errs = append(errs, stop)
	}

	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
}
