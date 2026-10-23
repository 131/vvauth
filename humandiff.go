package vvauth

import (
	"fmt"
	"math"
	"strings"
)

type diffStep struct {
	format string
	size   float64
}

// nyks/date/humanDiff FORMAT_LIGHT steps.
var diffSteps = []diffStep{
	{"%ds", 60}, {"%dm", 60}, {"%dh", 24}, {"%dd", 30}, {"%dmonth%s", 12}, {"%dy", 0},
}

// HumanDiff formats a duration in seconds with at most max units ("1d 3h"),
// like nyks/date/humanDiff.
func HumanDiff(seconds float64, max int) string {
	seconds = math.Ceil(seconds)
	if seconds == 0 {
		return "0s"
	}
	var parts []string
	for _, step := range diffSteps {
		var current float64
		if step.size == 0 {
			current = math.Floor(seconds)
		} else {
			current = math.Floor(math.Mod(seconds, step.size))
			seconds /= step.size
		}
		if current > 0 {
			plural := ""
			if current > 1 {
				plural = "s"
			}
			parts = append(parts, fmt.Sprintf(strings.Replace(step.format, "%s", plural, 1), int64(current)))
		}
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	if len(parts) > max {
		parts = parts[:max]
	}
	return strings.Join(parts, " ")
}
