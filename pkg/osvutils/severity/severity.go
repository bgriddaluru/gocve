package severity

import (
	"fmt"
	"math"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/models"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// GetSeverity returns a CVSS rating or an Ubuntu priority.
func GetSeverity(assessment models.Severity) (string, error) {
	_, rating, err := CalculateScore(assessment)
	return rating, err
}

// CalculateSeverity selects the highest CVSS score, falling back to Ubuntu priority.
// An empty assessment list returns an empty rating.
func CalculateSeverity(assessments []models.Severity) (string, error) {
	highestScore := -1.0
	cvssRating := "UNKNOWN"
	for _, assessment := range assessments {
		score, rating, err := CalculateScore(assessment)
		// println("Assessment Type:", assessment.Type, "Score:", assessment.Score, "Rating:", rating)
		if err != nil {
			return "", err
		}
		if score > highestScore {
			highestScore = score
			cvssRating = rating
		}
	}
	return cvssRating, nil
}

// CalculateScore derives a score and rating from an OSV severity assessment.
// It follows OSV-Scanner's scoring policy:
// https://github.com/google/osv-scanner/blob/084beec2c3ff907505e0da5671f898cfbb69361a/internal/utility/severity/severity.go
// CVSS v2 and v3 use base scores; v4 includes supplied threat and environmental metrics.
// CVSS v2 uses the v3 rating scale. Ubuntu returns its lowercase priority and a score of -1.
// Missing, unsupported, or invalid assessments return an error.
func CalculateScore(assessment models.Severity) (float64, string, error) {
	if assessment.Type == "Ubuntu" {
		switch assessment.Score {
		case "negligible", "low", "medium", "high", "critical":
			return -1, assessment.Score, nil
		default:
			return 0, "", fmt.Errorf("invalid Ubuntu priority %q", assessment.Score)
		}
	}
	score, err := cvssScore(assessment)
	if err != nil {
		return 0, "", fmt.Errorf("calculate %s score: %w", assessment.Type, err)
	}
	rating, err := severityFromScore(assessment.Type, score)
	if err != nil {
		return 0, "", fmt.Errorf("rate %s score: %w", assessment.Type, err)
	}
	return score, rating, nil
}

func cvssScore(assessment models.Severity) (float64, error) {
	switch assessment.Type {
	case "CVSS_V2":
		cvss, err := gocvss20.ParseVector(assessment.Score)
		if err != nil {
			return 0, err
		}
		return cvss.BaseScore(), nil
	case "CVSS_V3":
		if strings.HasPrefix(assessment.Score, "CVSS:3.0/") {
			cvss, err := gocvss30.ParseVector(assessment.Score)
			if err != nil {
				return 0, err
			}
			return cvss.BaseScore(), nil
		}
		cvss, err := gocvss31.ParseVector(assessment.Score)
		if err != nil {
			return 0, err
		}
		return cvss.BaseScore(), nil
	case "CVSS_V4":
		cvss, err := gocvss40.ParseVector(assessment.Score)
		if err != nil {
			return 0, err
		}
		return cvss.Score(), nil
	default:
		return 0, fmt.Errorf("unsupported CVSS type %q", assessment.Type)
	}
}

func severityFromScore(scoreType string, score float64) (string, error) {
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 10 {
		return "", fmt.Errorf("invalid CVSS score %v: must be between 0 and 10", score)
	}
	switch scoreType {
	case "CVSS_V2", "CVSS_V3":
		return gocvss30.Rating(score)
	case "CVSS_V4":
		return gocvss40.Rating(score)
	default:
		return "", fmt.Errorf("unsupported CVSS type %q", scoreType)
	}
}
