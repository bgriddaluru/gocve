package models

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOSVRoundTrip(t *testing.T) {
	const payload = `{
		"schema_version": "1.9.2",
		"id": "GO-2026-0001",
		"modified": "2026-10-13T12:30:00.123456789Z",
		"published": "2026-10-12T12:30:00Z",
		"withdrawn": "2026-10-14T12:30:00Z",
		"aliases": ["CVE-2026-0001"],
		"upstream": ["GHSA-0000-0000-0000"],
		"related": ["GO-2026-0002"],
		"summary": "Example OSV",
		"details": "Example details",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "example.com/module", "purl": "pkg:golang/example.com/module"},
			"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "source": "NVD"}],
			"ranges": [
				{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}], "database_specific": {"precision": 9007199254740993}},
				{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.1.0"}]},
				{"type": "GIT", "repo": "https://example.com/repo", "events": [{"introduced": "0"}, {"limit": "0123456789abcdef0123456789abcdef01234567"}]}
			],
			"versions": ["1.0.0"],
			"ecosystem_specific": {"imports": [{"path": "example.com/module/sub", "symbols": ["Example"]}]},
			"database_specific": {"reviewed": true}
		}],
		"references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
		"credits": [{"name": "Example researcher", "contact": ["https://example.com/researcher"], "type": "FINDER"}],
		"database_specific": {"nested": {"values": [true, null, 9007199254740993]}}
	}`
	var vuln OSV
	if err := json.Unmarshal([]byte(payload), &vuln); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(vuln)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	// Raw messages also ensure that large numbers in extension objects are preserved exactly.
	if err := json.Unmarshal([]byte(payload), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed record: %s", encoded)
	}
	if string(vuln.Affected[0].Ranges[0].DatabaseSpecific["precision"]) != "9007199254740993" {
		t.Fatal("extension number lost precision")
	}
	var decoded OSV
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Affected[0].Ranges[0].DatabaseSpecific["precision"]) != "9007199254740993" {
		t.Fatal("round trip lost extension number precision")
	}
}

func TestOSVOptionalFields(t *testing.T) {
	for _, payload := range []string{
		`{"id":"GO-2026-0001","modified":"2026-10-13T12:30:00Z"}`,
		`{"id":"GO-2026-0001","modified":"2026-10-13T12:30:00Z","aliases":null,"affected":null,"references":null,"severity":null}`,
		`{"id":"GO-2026-0001","modified":"2026-10-13T12:30:00Z","severity":[{"type":"Ubuntu","score":"high"}],"affected":[{"versions":["1.0.0"]}]}`,
	} {
		var vuln OSV
		if err := json.Unmarshal([]byte(payload), &vuln); err != nil {
			t.Fatal(err)
		}
		if vuln.Published != nil || vuln.Withdrawn != nil {
			t.Fatal("absent dates must remain nil")
		}
		encoded, err := json.Marshal(vuln)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"schema_version", "published", "withdrawn"} {
			if _, exists := fields[name]; exists {
				t.Fatalf("absent optional field %s was emitted", name)
			}
		}
		if len(vuln.Affected) > 0 && vuln.Affected[0].Package != nil {
			t.Fatal("absent package identity must remain nil")
		}
	}
}
