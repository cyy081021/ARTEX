package db

import (
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

const nativeCampaignCanonicalHex = "0123456789abcdef"

// AppendNativeCampaignCanonicalString encodes the protocol UTF-8 JSON string.
// This shared encoder deliberately preserves HTML and Unicode separators.
func AppendNativeCampaignCanonicalString(dst []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, fmt.Errorf("canonical JSON string is not valid UTF-8")
	}
	dst = append(dst, '"')
	for _, r := range value {
		switch r {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if r < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0',
					nativeCampaignCanonicalHex[(r>>4)&0xf], nativeCampaignCanonicalHex[r&0xf])
			} else {
				// Like Python's ensure_ascii=False encoder: non-ASCII UTF-8,
				// '<', '>', '&', U+2028 and U+2029 stay unescaped.
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"'), nil
}

// CanonicalNativeCampaignManifest is the single byte-compatible Python manifest
// encoder. Callers validate identities, bounds and entry ownership separately.
func CanonicalNativeCampaignManifest(campaignID, attemptID int64, records []NativeCampaignEntryInput) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("checkpoint manifest has no entries")
	}
	sortedRecords := make([]NativeCampaignEntryInput, len(records))
	copy(sortedRecords, records)
	sort.Slice(sortedRecords, func(i, j int) bool {
		left, right := sortedRecords[i], sortedRecords[j]
		if left.SourceType != right.SourceType {
			return left.SourceType < right.SourceType
		}
		if left.StorageKey != right.StorageKey {
			return left.StorageKey < right.StorageKey
		}
		if left.SHA256 != right.SHA256 {
			return left.SHA256 < right.SHA256
		}
		return left.Length < right.Length
	})
	out := make([]byte, 0, 256+len(sortedRecords)*320)
	out = append(out, `{"attempt_id":`...)
	out = strconv.AppendInt(out, attemptID, 10)
	out = append(out, `,"campaign_id":`...)
	out = strconv.AppendInt(out, campaignID, 10)
	out = append(out, `,"entries":[`...)
	var err error
	for index, record := range sortedRecords {
		if index > 0 {
			out = append(out, ',')
		}
		out = append(out, `{"length":`...)
		out = strconv.AppendInt(out, int64(record.Length), 10)
		out = append(out, `,"sha256":`...)
		if out, err = AppendNativeCampaignCanonicalString(out, record.SHA256); err != nil {
			return nil, err
		}
		out = append(out, `,"source_ref":`...)
		if out, err = AppendNativeCampaignCanonicalString(out, record.SourceRef); err != nil {
			return nil, err
		}
		out = append(out, `,"source_type":`...)
		if out, err = AppendNativeCampaignCanonicalString(out, record.SourceType); err != nil {
			return nil, err
		}
		out = append(out, `,"storage_key":`...)
		if out, err = AppendNativeCampaignCanonicalString(out, record.StorageKey); err != nil {
			return nil, err
		}
		out = append(out, '}')
	}
	out = append(out, `],"format_version":1}`...)
	return out, nil
}
