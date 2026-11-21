package db

// stripNativeCampaignArchiveTables removes the Campaign sections from a snapshot that a
// test deliberately downgrades to a pre-v6 format version. v6 archives always carry the
// Campaign graph, and the restore gate rejects a legacy package that smuggles Campaign
// tables, so a legacy fixture must look exactly like what an old exporter produced.
func stripNativeCampaignArchiveTables(s *TaskArchiveSnapshot) {
	if s == nil {
		return
	}
	for _, name := range nativeCampaignArchiveTables {
		delete(s.Tables, name)
		delete(s.DataCounts, name)
	}
}
