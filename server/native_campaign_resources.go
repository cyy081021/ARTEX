package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// Resource plans are server-generated capabilities, never campaign spec input.
// Absence is a legacy execution without a durable creation seal. A present but
// invalid plan is an error, never a request to downgrade.
type nativeCampaignResourcePlan struct {
	Version         int      `json:"version"`
	TaskID          int64    `json:"task_id"`
	CampaignID      int64    `json:"campaign_id"`
	AttemptID       int64    `json:"attempt_id"`
	FencingToken    int64    `json:"fencing_token"`
	StagingRoot     string   `json:"staging_root"`
	StagingBasename string   `json:"staging_basename"`
	ContainerNames  []string `json:"container_names"`
}

func nativeCampaignResourceNames(campaign, attempt, fence int64) []string {
	base := fmt.Sprintf("artex-campaign-%d-%d-%d-%d", campaign, attempt, attempt, fence)
	return []string{base, base + "-help-afl-fuzz", base + "-help-afl-showmap", base + "-probe"}
}

func (p *nativeCampaignResourcePlan) validate(task, campaign, attempt, fence int64) error {
	if p == nil {
		return nil
	}
	if p.Version != 1 || p.TaskID != task || p.CampaignID != campaign || p.AttemptID != attempt || p.FencingToken != fence || task <= 0 || campaign <= 0 || attempt <= 0 || fence <= 0 {
		return errors.New("resource plan identity/version mismatch")
	}
	// Runner paths are POSIX paths even when the manager host is Windows.
	if len(p.StagingRoot) > 4096 || p.StagingRoot == "/" || !path.IsAbs(p.StagingRoot) || path.Clean(p.StagingRoot) != p.StagingRoot || strings.ContainsAny(p.StagingRoot, "\\\x00\r\n") {
		return errors.New("resource plan requires a canonical absolute POSIX private root")
	}
	names := nativeCampaignResourceNames(campaign, attempt, fence)
	if len(p.ContainerNames) != len(names) || p.StagingBasename != names[0]+"-stage" {
		return errors.New("resource plan names mismatch")
	}
	for i := range names {
		if p.ContainerNames[i] != names[i] {
			return errors.New("resource plan names mismatch")
		}
	}
	return nil
}

// Digest bytes are an ordered JSON array, not the plan object's wire encoding:
// [version,task,campaign,attempt,fence,root,basename,[four names]]. Strings use
// the existing cross-language canonical UTF-8 encoder (no HTML/ASCII escaping).
func (p *nativeCampaignResourcePlan) digest() (string, error) {
	if p == nil {
		return "", errors.New("missing resource plan")
	}
	if err := p.validate(p.TaskID, p.CampaignID, p.AttemptID, p.FencingToken); err != nil {
		return "", err
	}
	out := []byte(fmt.Sprintf("[%d,%d,%d,%d,%d,", p.Version, p.TaskID, p.CampaignID, p.AttemptID, p.FencingToken))
	var err error
	for _, value := range []string{p.StagingRoot, p.StagingBasename} {
		out, err = appendNativeCampaignCanonicalString(out, value)
		if err != nil {
			return "", err
		}
		out = append(out, ',')
	}
	out = append(out, '[')
	for i, value := range p.ContainerNames {
		if i > 0 {
			out = append(out, ',')
		}
		out, err = appendNativeCampaignCanonicalString(out, value)
		if err != nil {
			return "", err
		}
	}
	out = append(out, ']', ']')
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

func nativeCampaignPlanFromResources(raw json.RawMessage) (*nativeCampaignResourcePlan, error) {
	var envelope map[string]json.RawMessage
	if len(raw) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	value, ok := envelope["resource_plan"]
	if !ok {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, errors.New("null resource plan")
	}
	var plan nativeCampaignResourcePlan
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return nil, err
	}
	return &plan, nil
}

type nativeCampaignCreationContainer struct {
	Name   string            `json:"name"`
	ID     string            `json:"id"`
	Labels map[string]string `json:"labels"`
}
type nativeCampaignCreationSeal struct {
	Version         int                               `json:"version"`
	TaskID          int64                             `json:"task_id"`
	CampaignID      int64                             `json:"campaign_id"`
	AttemptID       int64                             `json:"attempt_id"`
	FencingToken    int64                             `json:"fencing_token"`
	PlanSHA256      string                            `json:"plan_sha256"`
	StagingBasename string                            `json:"staging_basename"`
	Containers      []nativeCampaignCreationContainer `json:"containers"`
}

func (s *nativeCampaignCreationSeal) validate(p *nativeCampaignResourcePlan) error {
	if s == nil {
		return nil
	}
	if p == nil {
		return errors.New("creation seal without resource plan")
	}
	digest, err := p.digest()
	if err != nil {
		return err
	}
	if s.Version != 1 || s.TaskID != p.TaskID || s.CampaignID != p.CampaignID || s.AttemptID != p.AttemptID || s.FencingToken != p.FencingToken || s.PlanSHA256 != digest || s.StagingBasename != p.StagingBasename || len(s.Containers) < 1 || len(s.Containers) > 4 {
		return errors.New("creation seal binding mismatch")
	}
	labels := map[string]string{"artex.task_id": fmt.Sprint(p.TaskID), "artex.campaign_id": fmt.Sprint(p.CampaignID), "artex.attempt_id": fmt.Sprint(p.AttemptID), "artex.fencing_token": fmt.Sprint(p.FencingToken), "artex.owner": "artex-native-campaign"}
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, c := range s.Containers {
		allowed := false
		for _, name := range p.ContainerNames {
			if c.Name == name {
				allowed = true
			}
		}
		raw, err := hex.DecodeString(c.ID)
		if !allowed || names[c.Name] || ids[c.ID] || err != nil || len(raw) != 32 || strings.ToLower(c.ID) != c.ID || len(c.Labels) != len(labels) {
			return errors.New("creation seal container mismatch")
		}
		for key, value := range labels {
			if c.Labels[key] != value {
				return errors.New("creation seal labels mismatch")
			}
		}
		names[c.Name] = true
		ids[c.ID] = true
	}
	return nil
}

// Until cleanup consumes the complete sealed CID set, generic cleanup reports
// cannot release any new-plan attempt, including failed startup compensation.
func nativeCampaignRequiresSealedCleanup(raw json.RawMessage) bool {
	plan, err := nativeCampaignPlanFromResources(raw)
	return err != nil || plan != nil
}

func nativeCampaignSealFromResources(raw json.RawMessage) (*nativeCampaignCreationSeal, error) {
	var resources map[string]json.RawMessage
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, err
	}
	value, ok := resources["creation_seal"]
	if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, errors.New("durable creation seal missing")
	}
	var seal nativeCampaignCreationSeal
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seal); err != nil {
		return nil, err
	}
	return &seal, nil
}
func (r nativeCampaignCleanupReport) verifiedFor(plan *nativeCampaignResourcePlan, seal *nativeCampaignCreationSeal) bool {
	if plan == nil || seal == nil || seal.validate(plan) != nil || !r.verified() || r.PlanSHA256 != seal.PlanSHA256 || r.StagingBasename != plan.StagingBasename || len(r.Containers) != len(seal.Containers) {
		return false
	}
	expected := map[string]string{}
	for _, item := range seal.Containers {
		expected[item.ID] = item.Name
	}
	for _, item := range r.Containers {
		name, ok := expected[item.ID]
		if !ok || name != item.Name {
			return false
		}
		delete(expected, item.ID)
	}
	return len(expected) == 0
}
