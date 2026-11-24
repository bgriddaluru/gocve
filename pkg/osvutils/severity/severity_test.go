package severity

import (
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
)

func TestCalculateScore(t *testing.T) {
	for _, tc := range []struct {
		name       string
		assessment models.Severity
		score      float64
		rating     string
	}{
		{"v2", models.Severity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}, 10, "CRITICAL"},
		{"v30", models.Severity{Type: "CVSS_V3", Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, 9.8, "CRITICAL"},
		{"v31", models.Severity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}, 5.3, "MEDIUM"},
		{"v4", models.Severity{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, 9.3, "CRITICAL"},
		{"Ubuntu", models.Severity{Type: "Ubuntu", Score: "high"}, -1, "high"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			score, rating, err := CalculateScore(tc.assessment)
			if err != nil || score != tc.score || rating != tc.rating {
				t.Fatalf("got (%v, %q, %v), want (%v, %q, nil)", score, rating, err, tc.score, tc.rating)
			}
			got, err := GetSeverity(tc.assessment)
			if err != nil || got != rating {
				t.Fatalf("GetSeverity = %q, %v; want %q", got, err, rating)
			}
		})
	}
}

func TestCalculateScoreRejectsInvalidInput(t *testing.T) {
	for _, assessment := range []models.Severity{
		{},
		{Type: "CVSS_V3", Score: "5.3"},
		{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N"},
		{Type: "Ubuntu", Score: "unknown"},
	} {
		score, rating, err := CalculateScore(assessment)
		if err == nil || score != 0 || rating != "" {
			t.Fatalf("CalculateScore(%+v) = %v, %q, %v", assessment, score, rating, err)
		}

	}
}

func TestCVSS4UsesOptionalMetrics(t *testing.T) {
	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	score, rating, err := CalculateScore(models.Severity{Type: "CVSS_V4", Score: base + "/E:U/MAV:P/MVC:N/MVI:N/MVA:N"})
	if err != nil {
		t.Fatal(err)
	}
	if score != 0 || rating != "NONE" {
		t.Fatalf("got %v %q, want 0 NONE", score, rating)
	}
}

func TestHighestSeverity(t *testing.T) {
	v2 := models.Severity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}
	v3 := models.Severity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}
	v4 := models.Severity{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
	v4Zero := models.Severity{Type: "CVSS_V4", Score: v4.Score + "/E:U/MAV:P/MVC:N/MVI:N/MVA:N"}
	zero := models.Severity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
	ubuntuHigh := models.Severity{Type: "Ubuntu", Score: "high"}
	ubuntuLow := models.Severity{Type: "Ubuntu", Score: "low"}
	for _, tc := range []struct {
		name        string
		assessments []models.Severity
		rating      string
	}{
		{"missing", nil, "UNKNOWN"},
		{"highest not first", []models.Severity{v3, v2, v4}, "CRITICAL"},
		{"highest first", []models.Severity{v2, v4, v3}, "CRITICAL"},
		{"score rather than version", []models.Severity{v4Zero, v3}, "MEDIUM"},
		{"Ubuntu highest last", []models.Severity{ubuntuLow, ubuntuHigh}, "high"},
		{"Ubuntu highest first", []models.Severity{ubuntuHigh, ubuntuLow}, "high"},
		{"CVSS preferred", []models.Severity{ubuntuHigh, v3}, "MEDIUM"},
		{"CVSS preferred reversed", []models.Severity{v3, ubuntuHigh}, "MEDIUM"},
		{"zero CVSS preferred", []models.Severity{ubuntuHigh, zero}, "NONE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rating, err := CalculateSeverity(tc.assessments)
			if err != nil || rating != tc.rating {
				t.Fatalf("HighestSeverity = %q, %v; want %q, nil", rating, err, tc.rating)
			}
		})
	}
}

func TestHighestSeverityRejectsInvalidAssessment(t *testing.T) {
	valid := models.Severity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}
	for _, invalid := range []models.Severity{
		{Type: "CVSS_V3", Score: "invalid"},
		{Type: "Ubuntu", Score: "unknown"},
		{Type: "unsupported"},
	} {
		rating, err := CalculateSeverity([]models.Severity{valid, invalid})
		if err == nil || rating != "" {
			t.Fatalf("HighestSeverity with %+v = %q, %v; want empty rating and error", invalid, rating, err)
		}
	}
}
