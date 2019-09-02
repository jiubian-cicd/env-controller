package gits

import (
	"strings"
)

type CommitInfo struct {
	Kind    string
	Feature string
	Message string
	group   *CommitGroup
}

type CommitGroup struct {
	Title string
	Order int
}

var (
	groupCounter = 0

	// ConventionalCommitTitles textual descriptions for
	// Conventional Commit types: https://conventionalcommits.org/
	ConventionalCommitTitles = map[string]*CommitGroup{
		"feat":     createCommitGroup("New Features"),
		"fix":      createCommitGroup("Bug Fixes"),
		"perf":     createCommitGroup("Performance Improvements"),
		"refactor": createCommitGroup("Code Refactoring"),
		"docs":     createCommitGroup("Documentation"),
		"test":     createCommitGroup("Tests"),
		"revert":   createCommitGroup("Reverts"),
		"style":    createCommitGroup("Styles"),
		"chore":    createCommitGroup("Chores"),
		"":         createCommitGroup(""),
	}

	unknownKindOrder = groupCounter + 1
)

func createCommitGroup(title string) *CommitGroup {
	groupCounter += 1
	return &CommitGroup{
		Title: title,
		Order: groupCounter,
	}
}

// ConventionalCommitTypeToTitle returns the title of the conventional commit type
// see: https://conventionalcommits.org/
func ConventionalCommitTypeToTitle(kind string) *CommitGroup {
	answer := ConventionalCommitTitles[strings.ToLower(kind)]
	if answer == nil {
		answer = &CommitGroup{strings.Title(kind), unknownKindOrder}
	}
	return answer
}

// ParseCommit parses a conventional commit
// see: https://conventionalcommits.org/
func ParseCommit(message string) *CommitInfo {
	answer := &CommitInfo{
		Message: message,
	}

	idx := strings.Index(message, ":")
	if idx > 0 {
		kind := message[0:idx]
		if strings.HasSuffix(kind, ")") {
			idx := strings.Index(kind, "(")
			if idx > 0 {
				answer.Feature = strings.TrimSpace(kind[idx+1 : len(kind)-1])
				kind = strings.TrimSpace(kind[0:idx])
			}
		}
		answer.Kind = kind
		rest := strings.TrimSpace(message[idx+1:])

		answer.Message = rest
	}
	return answer
}

func (c *CommitInfo) Group() *CommitGroup {
	if c.group == nil {
		c.group = ConventionalCommitTitles[strings.ToLower(c.Kind)]
	}
	return c.group
}

func (c *CommitInfo) Title() string {
	return c.Group().Title
}

func (c *CommitInfo) Order() int {
	return c.Group().Order
}

type GroupAndCommitInfos struct {
	group   *CommitGroup
	commits []string
}


