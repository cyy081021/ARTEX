package db

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalNativeCampaignManifestShared(t *testing.T) {
	r := NativeCampaignEntryInput{Length: 1, SHA256: strings.Repeat("a", 64), SourceRef: "种子/<>&\u2028\u2029", SourceType: "seed", StorageKey: "tasks/1/object"}
	raw, err := CanonicalNativeCampaignManifest(2, 3, []NativeCampaignEntryInput{r})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"attempt_id":3,"campaign_id":2,"entries":[{"length":1,"sha256":"` + r.SHA256 + `","source_ref":"` + r.SourceRef + `","source_type":"seed","storage_key":"tasks/1/object"}],"format_version":1}`
	if string(raw) != want {
		t.Fatalf("canonical bytes differ: %q", raw)
	}
	if _, err := CanonicalNativeCampaignManifest(2, 3, nil); err == nil {
		t.Fatal("empty manifest accepted")
	}
	r.SourceRef = string([]byte{255})
	if _, err := CanonicalNativeCampaignManifest(2, 3, []NativeCampaignEntryInput{r}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	a := NativeCampaignEntryInput{Length: 1, SourceType: "seed", StorageKey: "b"}
	b := NativeCampaignEntryInput{Length: 1, SourceType: "queue", StorageKey: "a"}
	input := []NativeCampaignEntryInput{a, b}
	x, _ := CanonicalNativeCampaignManifest(2, 3, input)
	y, _ := CanonicalNativeCampaignManifest(2, 3, []NativeCampaignEntryInput{b, a})
	if !bytes.Equal(x, y) || input[0] != a {
		t.Fatal("sorting is unstable or mutates caller")
	}
}
