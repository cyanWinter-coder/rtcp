// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// unboundedLimits disables every limit, for tests that only exercise parsing.
func unboundedLimits() PartialCompoundLimits {
	return PartialCompoundLimits{MaxPackets: -1, MaxTotalBytes: -1, MaxPacketBytes: -1}
}

func TestUnmarshalPartialEmpty(t *testing.T) {
	report, err := UnmarshalPartial(nil, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Empty(t, report.Entries)
	assert.Empty(t, report.Packets)
	assert.Nil(t, report.Err)
}

func TestUnmarshalPartialValid(t *testing.T) {
	data := realPacket()

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.Nil(t, report.Err)
	assert.Len(t, report.Entries, 6)
	assert.Len(t, report.Packets, 6)
	assert.NoError(t, report.Packets.Validate())

	offsets := []int{0, 32, 84, 92, 104, 116}
	lengths := []int{32, 52, 8, 12, 12, 16}
	for i, entry := range report.Entries {
		assert.Equalf(t, i, entry.Index, "entry %d index", i)
		assert.Equalf(t, offsets[i], entry.Offset, "entry %d offset", i)
		assert.Equalf(t, lengths[i], entry.Length, "entry %d length", i)
		assert.Equalf(t, data[offsets[i]:offsets[i]+lengths[i]], entry.Raw, "entry %d raw", i)
		assert.Equalf(t, data[offsets[i]:offsets[i]+lengths[i]], marshaledPacket(entry), "entry %d packet bytes", i)
		assert.NoErrorf(t, entry.Err, "entry %d error", i)
		assert.NotNilf(t, entry.Packet, "entry %d packet", i)
	}
}

// marshaledPacket marshals the decoded packet, so a valid entry can be
// compared against its raw range.
func marshaledPacket(entry PartialCompoundEntry) []byte {
	if entry.Packet == nil {
		return nil
	}
	data, err := entry.Packet.Marshal()
	if err != nil {
		return nil
	}

	return data
}

func TestUnmarshalPartialCorruptMiddle(t *testing.T) {
	data := realPacket()
	// Turn the SDES packet (offset 32) into one with a chunk count of five,
	// which its single chunk cannot satisfy.
	data[32] = 0x85

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})

	var packetErr *PartialPacketError
	assert.ErrorAs(t, err, &packetErr)
	assert.ErrorIs(t, err, ErrPartialCompoundCorrupt)

	// Every other subpacket is preserved, including the ones after the
	// damaged slot, because the declared length still locates them.
	assert.Len(t, report.Entries, 6)
	assert.Len(t, report.Packets, 5)
	assert.Equal(t, []int{0, 84, 92, 104, 116}, entryOffsets(report.Entries, true))
	assert.Equal(t, err, report.Err)

	damaged := report.Entries[1]
	assert.Equal(t, 1, damaged.Index)
	assert.Equal(t, 32, damaged.Offset)
	assert.Equal(t, 52, damaged.Length)
	assert.Nil(t, damaged.Packet)
	assert.ErrorIs(t, damaged.Err, ErrPartialCompoundCorrupt)

	assert.Equal(t, 1, packetErr.Index)
	assert.Equal(t, 32, packetErr.Offset)
}

func TestUnmarshalPartialIncompleteTail(t *testing.T) {
	for _, test := range []struct {
		Name        string
		Data        []byte
		Entries     int
		TailIndex   int
		TailOffset  int
		Length      int
		Type        PacketType
		ValidPrefix int
	}{
		{
			// A few bytes, less than a header: never a packet of its own.
			Name:        "short tail",
			Data:        append(realPacket(), 0x80, 0xc8),
			Entries:     7,
			TailIndex:   6,
			TailOffset:  132,
			Length:      2,
			ValidPrefix: 6,
		},
		{
			// A full header whose declared length overruns the datagram. The
			// tail is reported once and parsing stops.
			Name:        "declared length overruns",
			Data:        realPacket()[:36],
			Entries:     2,
			TailIndex:   1,
			TailOffset:  32,
			Length:      52,
			Type:        TypeSourceDescription,
			ValidPrefix: 1,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			report, err := UnmarshalPartial(test.Data, PartialCompoundLimits{})

			assert.ErrorIs(t, err, ErrPartialCompoundTruncated)
			assert.ErrorIs(t, report.Err, ErrPartialCompoundTruncated)
			assert.Len(t, report.Entries, test.Entries)

			tail := report.Entries[test.TailIndex]
			assert.Equal(t, test.TailIndex, tail.Index)
			assert.Equal(t, test.TailOffset, tail.Offset)
			assert.Equal(t, test.Length, tail.Length)
			assert.Equal(t, test.Type, tail.Type)
			assert.Equal(t, test.Data[tail.Offset:], tail.Raw)
			assert.Nil(t, tail.Packet)

			var packetErr *PartialPacketError
			assert.ErrorAs(t, tail.Err, &packetErr)
			assert.Equal(t, test.TailIndex, packetErr.Index)
			assert.Equal(t, tail.Offset, packetErr.Offset)

			// The strictly valid prefix is still returned.
			assert.Len(t, report.Packets, test.ValidPrefix)
		})
	}
}

func TestUnmarshalPartialUnknownType(t *testing.T) {
	unknown := []byte{0x80, 0xc3, 0x00, 0x00} // PT=195, length 0
	pli := []byte{0x81, 0xce, 0x00, 0x02, 0x90, 0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e}
	data := append(append([]byte{}, unknown...), pli...)

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.Len(t, report.Entries, 2)

	first := report.Entries[0]
	assert.Equal(t, PacketType(195), first.Type)
	assert.Equal(t, unknown, first.Raw)
	raw, ok := first.Packet.(*RawPacket)
	assert.True(t, ok)
	assert.Equal(t, RawPacket(unknown), *raw)

	_, ok = report.Entries[1].Packet.(*PictureLossIndication)
	assert.True(t, ok)
}

func TestUnmarshalPartialBadVersionResync(t *testing.T) {
	// An unknown-type packet with version 0, followed by a valid PLI.
	bad := []byte{0x00, 0xc3, 0x00, 0x00}
	pli := []byte{0x81, 0xce, 0x00, 0x02, 0x90, 0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e}
	data := append(append([]byte{}, bad...), pli...)

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.ErrorIs(t, err, ErrPartialCompoundCorrupt)

	damaged := report.Entries[0]
	assert.Equal(t, 0, damaged.Offset)
	assert.Equal(t, 4, damaged.Length)
	assert.ErrorIs(t, damaged.Err, errBadVersion)
	assert.ErrorIs(t, damaged.Err, ErrPartialCompoundCorrupt)

	// Parsing resynchronizes at the next header.
	assert.Len(t, report.Entries, 2)
	assert.Len(t, report.Packets, 1)
	_, ok := report.Packets[0].(*PictureLossIndication)
	assert.True(t, ok)
}

func TestUnmarshalPartialLimits(t *testing.T) {
	data := realPacket()

	for _, test := range []struct {
		Name    string
		Limits  PartialCompoundLimits
		Entries int
		StopAt  int
		Err     error
	}{
		{
			Name:    "max packets",
			Limits:  PartialCompoundLimits{MaxPackets: 2},
			Entries: 2,
			StopAt:  84,
			Err:     ErrPartialCompoundTooManyPackets,
		},
		{
			Name:    "max total bytes",
			Limits:  PartialCompoundLimits{MaxTotalBytes: 40},
			Entries: 1,
			StopAt:  32,
			Err:     ErrPartialCompoundTooManyBytes,
		},
		{
			Name:    "max packet bytes",
			Limits:  PartialCompoundLimits{MaxPacketBytes: 40},
			Entries: 1,
			StopAt:  32,
			Err:     ErrPartialCompoundPacketTooLarge,
		},
		{
			Name:    "max packet bytes rejects first",
			Limits:  PartialCompoundLimits{MaxPacketBytes: 8},
			Entries: 0,
			StopAt:  0,
			Err:     ErrPartialCompoundPacketTooLarge,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			report, err := UnmarshalPartial(data, test.Limits)

			assert.ErrorIs(t, err, test.Err)
			assert.ErrorIs(t, report.Err, test.Err)

			var compoundErr *PartialCompoundError
			assert.ErrorAs(t, report.Err, &compoundErr)
			assert.Equal(t, test.StopAt, compoundErr.Offset)

			// Parsing stops before allocating the offending entry.
			assert.Len(t, report.Entries, test.Entries)
			assert.Len(t, report.Packets, test.Entries)
		})
	}
}

func TestPartialErrorsString(t *testing.T) {
	data := realPacket()
	data[32] = 0x85

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.Error(t, err)
	assert.Len(t, report.Entries, 6)

	var packetErr *PartialPacketError
	assert.ErrorAs(t, err, &packetErr)
	assert.Contains(t,
		packetErr.Error(), "rtcp: subpacket 1 at offset 32 (length 52, type 202):")

	limited, stopErr := UnmarshalPartial(data, PartialCompoundLimits{MaxPackets: 1})

	var compoundErr *PartialCompoundError
	assert.ErrorAs(t, stopErr, &compoundErr)
	assert.Contains(t, compoundErr.Error(), "rtcp: partial compound stopped at offset 32 (length 52, limit 1)")

	// The one inspected entry is the intact RR; the stop error is only in
	// report.Err.
	assert.Len(t, limited.Entries, 1)
	assert.NoError(t, limited.Entries[0].Err)
	assert.ErrorIs(t, limited.Err, ErrPartialCompoundTooManyPackets)
}

func TestUnmarshalPartialLimitNotExceeded(t *testing.T) {
	data := realPacket()

	// Limits that exactly cover the datagram must not stop it.
	report, err := UnmarshalPartial(data, PartialCompoundLimits{
		MaxPackets:     6,
		MaxTotalBytes:  len(data),
		MaxPacketBytes: 52,
	})
	assert.NoError(t, err)
	assert.Len(t, report.Entries, 6)
	assert.Len(t, report.Packets, 6)
}

func TestUnmarshalPartialLimitZeroAndNegative(t *testing.T) {
	// One-byte payload unknown packets: 4 bytes each.
	data := bytes.Repeat([]byte{0x80, 0xc3, 0x00, 0x00}, 8)

	// Zero selects the defaults, which comfortably allow the datagram.
	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.Len(t, report.Entries, 8)

	// A negative limit disables that field. MaxPackets is the only one that
	// could bind here, and disabling it yields the same result.
	report, err = UnmarshalPartial(data, unboundedLimits())
	assert.NoError(t, err)
	assert.Len(t, report.Entries, 8)
}

func TestUnmarshalPartialDoesNotModifyInput(t *testing.T) {
	data := realPacket()
	original := append([]byte{}, data...)

	_, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.Equal(t, original, data)

	// Corrupting a slot must not change the input either.
	data[32] = 0x85
	original = append([]byte{}, data...)
	_, _ = UnmarshalPartial(data, PartialCompoundLimits{})
	assert.Equal(t, original, data)
}

// Raw is a view with a capped capacity, so appending to the first entry can
// never overwrite the packet that follows it.
func TestUnmarshalPartialRawCapacity(t *testing.T) {
	data := []byte{
		0x80, 0xc3, 0x00, 0x00, // unknown type, length 0
		0x80, 0xc4, 0x00, 0x00, // unknown type, length 0
	}

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.Len(t, report.Entries, 2)

	_ = append(report.Entries[0].Raw, 0xff, 0xff)
	assert.Equal(t, []byte{0x80, 0xc4, 0x00, 0x00}, report.Entries[1].Raw)
}

func TestUnmarshalPartialPreservesStrictValidate(t *testing.T) {
	// A valid compound: RR, SDES with CNAME, BYE.
	valid := CompoundPacket{
		&ReceiverReport{},
		NewCNAMESourceDescription(1234, "cname"),
		&Goodbye{Sources: []uint32{1234}},
	}
	data, err := valid.Marshal()
	assert.NoError(t, err)

	report, err := UnmarshalPartial(data, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.NoError(t, report.Packets.Validate())

	// The strict entry points still behave exactly as before: Unmarshal keeps
	// rejecting a payload whose slot violates the compound rules.
	bad := realPacket()[84:104] // BYE, PLI: not starting with SR/RR
	packets, err := Unmarshal(bad)
	assert.NoError(t, err)
	assert.ErrorIs(t, CompoundPacket(packets).Validate(), errBadFirstPacket)

	report, err = UnmarshalPartial(bad, PartialCompoundLimits{})
	assert.NoError(t, err)
	assert.Len(t, report.Packets, 2)
	assert.ErrorIs(t, report.Packets.Validate(), errBadFirstPacket)

	// And a datagram Unmarshal cannot parse at all is still rejected by it,
	// while the partial entry point reports the damaged middle slot.
	corrupted := realPacket()
	corrupted[32] = 0x85
	_, err = Unmarshal(corrupted)
	assert.Error(t, err)

	// The valid subset is still subject to the unchanged strict rules: the
	// CNAME is in the damaged slot, so the remaining BYE and feedback follow
	// without it.
	report, err = UnmarshalPartial(corrupted, PartialCompoundLimits{})
	assert.ErrorIs(t, err, ErrPartialCompoundCorrupt)
	assert.Len(t, report.Packets, 5)
	assert.ErrorIs(t, report.Packets.Validate(), errPacketBeforeCNAME)
}

func entryOffsets(entries []PartialCompoundEntry, validOnly bool) []int {
	offsets := make([]int, 0, len(entries))
	for _, entry := range entries {
		if validOnly && entry.Err != nil {
			continue
		}
		offsets = append(offsets, entry.Offset)
	}

	return offsets
}

func FuzzUnmarshalPartial(f *testing.F) {
	f.Add([]byte{})
	f.Add(realPacket())

	f.Fuzz(func(t *testing.T, data []byte) {
		original := append([]byte{}, data...)

		report, err := UnmarshalPartial(data, unboundedLimits())
		if !assert.NotNil(t, report) {
			return
		}
		assert.Equal(t, original, data, "UnmarshalPartial modified its input")

		assertPartialEntriesTile(t, report.Entries, len(data))

		// Whenever the strict parser succeeds, the partial parser agrees on
		// every packet and reports no failure.
		packets, strictErr := Unmarshal(data)
		if strictErr != nil {
			return
		}
		assert.NoError(t, err, "strict Unmarshal succeeded but UnmarshalPartial failed")
		assert.Len(t, report.Packets, len(packets))
	})
}

// assertPartialEntriesTile checks that the entries cover the datagram exactly
// once, in order, and that each entry is either a packet or an error.
func assertPartialEntriesTile(t *testing.T, entries []PartialCompoundEntry, size int) {
	t.Helper()

	next := 0
	for i, entry := range entries {
		if !assert.Equalf(t, i, entry.Index, "entry %d index", i) ||
			!assert.Equalf(t, next, entry.Offset, "entry %d offset", i) ||
			!assert.NotZerof(t, len(entry.Raw), "entry %d raw length", i) {
			return
		}
		assert.Equalf(t, (entry.Packet != nil) != (entry.Err != nil), true,
			"entry %d must have exactly one of packet and error", i)
		next = entry.Offset + len(entry.Raw)
	}
	assert.Equal(t, size, next, "entries must cover the datagram")
}
