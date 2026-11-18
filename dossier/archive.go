package dossier

import (
	"bytes"
	"errors"
)

// VerifyChildren re-derives component identities from the archived parent bytes.
// A checksum over the outer JSON alone cannot establish that relationship.
func (b *Bundle) VerifyChildren() error {
	type key struct{ Parent, Kind, Name, Hash string }
	children := map[key]bool{}
	for _, f := range b.Files {
		if f.Parent != "" {
			children[key{f.Parent, f.Kind, f.Name, f.Hash}] = true
		}
	}
	seen := map[[2]string]bool{}
	remaining := MaxBytes
	for _, f := range b.Files {
		if f.Kind != "source_archive" && !(f.Kind == "package" && bytes.HasPrefix(f.Data, []byte("PK\x03\x04"))) {
			continue
		}
		identity := [2]string{f.Hash, f.Kind}
		if seen[identity] {
			continue
		}
		seen[identity] = true
		files, err := Expand(f, remaining)
		if err != nil {
			return err
		}
		for i, part := range files {
			remaining -= len(part.Data)
			if i == 0 {
				continue
			}
			id := key{f.Hash, part.Kind, part.Name, Digest(part.Data)}
			if !children[id] {
				return errors.New("归档中的组件与父包内容不一致")
			}
			delete(children, id)
		}
	}
	if len(children) > 0 {
		return errors.New("归档包含无法在父包中定位的材料")
	}
	return nil
}
