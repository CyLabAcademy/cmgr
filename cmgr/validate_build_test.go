package cmgr

import (
	"strings"
	"testing"
)

// validateBuild is the gate on a challenge's templated text: every artifact
// and lookup key it names must exist, and everything it publishes must be
// named by something. These assert on the offender each message names
// rather than on whole messages.

func buildFixture(lookups map[string]string) (*ChallengeMetadata, *BuildMetadata) {
	cMeta := &ChallengeMetadata{
		Id:           ChallengeId("example/challenge"),
		DeliveryType: DeliveryService,
	}
	bMeta := &BuildMetadata{
		Id:         BuildId(1),
		Challenge:  ChallengeId("example/challenge"),
		LookupData: lookups,
	}
	return cMeta, bMeta
}

// The clean case: every artifact and lookup key is referenced exactly once,
// across all three templated fields.
func TestValidateBuildAcceptsFullyReferenced(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(map[string]string{"port": "1337", "host": "example.org"})
	cMeta.Description = `Download {{url("handout.zip")}} and connect to {{lookup("host")}}.`
	cMeta.Details = `The service listens on {{lookup("port")}}.`
	cMeta.Hints = []string{`Start with {{url("hint.txt")}}.`}

	if err := m.validateBuild(cMeta, bMeta, []string{"handout.zip", "hint.txt"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A challenge with no templating and nothing published is valid; the loader
// reaches here for every build, not only templated ones.
func TestValidateBuildAcceptsNothingTemplated(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(nil)
	cMeta.Description = "A plain description with no references."

	if err := m.validateBuild(cMeta, bMeta, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Naming an artifact the build does not produce is the typo case: the player
// would be handed a dead link.
func TestValidateBuildRejectsUnknownArtifact(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(nil)
	cMeta.Description = `Download {{url("handout.zip")}}.`

	err := m.validateBuild(cMeta, bMeta, nil)
	if err == nil {
		t.Fatal("expected an error naming the unknown artifact")
	}
	if !strings.Contains(err.Error(), "handout.zip") {
		t.Fatalf("error does not name the bad reference: %v", err)
	}
}

// Same for a lookup key the build never recorded: the template would render
// empty rather than fail at solve time.
func TestValidateBuildRejectsUnknownLookup(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(nil)
	cMeta.Description = `Connect to {{lookup("hostname")}}.`

	err := m.validateBuild(cMeta, bMeta, nil)
	if err == nil {
		t.Fatal("expected an error naming the unknown lookup key")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("error does not name the bad reference: %v", err)
	}
}

// The other direction: publishing an artifact nothing references means the
// player is never told it exists, which is usually a forgotten reference.
func TestValidateBuildRejectsUnreferencedArtifact(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(nil)
	cMeta.Description = "No references here."

	err := m.validateBuild(cMeta, bMeta, []string{"orphan.zip"})
	if err == nil {
		t.Fatal("expected an error for the unreferenced artifact")
	}
	if !strings.Contains(err.Error(), "orphan.zip") {
		t.Fatalf("error does not name the unreferenced artifact: %v", err)
	}
}

// An unreferenced lookup value is the same mistake in the lookup map.
func TestValidateBuildRejectsUnreferencedLookup(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(map[string]string{"unused": "value"})
	cMeta.Description = "No references here."

	err := m.validateBuild(cMeta, bMeta, nil)
	if err == nil {
		t.Fatal("expected an error for the unreferenced lookup value")
	}
	if !strings.Contains(err.Error(), "unused") {
		t.Fatalf("error does not name the unreferenced lookup: %v", err)
	}
}

// References are collected from the details and the hints, not only the
// description, so an artifact named solely in a hint counts as used.
func TestValidateBuildCountsReferencesInHintsAndDetails(t *testing.T) {
	m := newTestManager()

	cMeta, bMeta := buildFixture(nil)
	cMeta.Details = `See {{url("only-in-details.zip")}}.`
	if err := m.validateBuild(cMeta, bMeta, []string{"only-in-details.zip"}); err != nil {
		t.Fatalf("a reference in the details did not count: %v", err)
	}

	cMeta, bMeta = buildFixture(nil)
	cMeta.Hints = []string{`See {{url("only-in-hint.zip")}}.`}
	if err := m.validateBuild(cMeta, bMeta, []string{"only-in-hint.zip"}); err != nil {
		t.Fatalf("a reference in a hint did not count: %v", err)
	}
}

// A bad reference in any one field fails the build even when the fields
// checked after it are clean: the later checks must not overwrite the verdict
// with a nil.
func TestValidateBuildDoesNotLoseAnEarlierFailure(t *testing.T) {
	m := newTestManager()

	// Bad description, clean details and hint.
	cMeta, bMeta := buildFixture(nil)
	cMeta.Description = `Download {{url("missing.zip")}}.`
	cMeta.Details = `Nothing templated here.`
	cMeta.Hints = []string{"Nor here."}
	if err := m.validateBuild(cMeta, bMeta, nil); err == nil {
		t.Fatal("a bad description was lost behind the clean fields after it")
	}

	// Bad hint, clean description and details.
	cMeta, bMeta = buildFixture(nil)
	cMeta.Description = "Nothing templated here."
	cMeta.Hints = []string{`See {{url("missing.zip")}}.`, "Nothing templated here."}
	if err := m.validateBuild(cMeta, bMeta, nil); err == nil {
		t.Fatal("a bad hint was lost behind the clean hint after it")
	}
}

// An artifact-only challenge that produces no artifacts hands the player
// nothing, but existing content still legitimately builds this way, so it
// warns rather than fails. Pinned because the comment marks it as a future
// hard error: this test says what has to change with it.
func TestValidateBuildOnlyWarnsForInertArtifactOnly(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(nil)
	cMeta.DeliveryType = DeliveryArtifactOnly
	cMeta.Description = "A description and nothing else."

	if err := m.validateBuild(cMeta, bMeta, nil); err != nil {
		t.Fatalf("an inert artifact-only challenge should warn, not fail: %v", err)
	}
}

// A challenge with more than one mistake reports all of them. The sweeps for
// published-but-unreferenced entries run after the reference checks, and used
// to report over whatever those had found: a challenge that both named a
// missing 'handout.zip' and published an unused 'handout.tar.gz' failed with a
// message about the unused file alone, saying nothing about the typo that was
// the likelier cause of both.
func TestValidateBuildReportsEveryProblem(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(map[string]string{"unused_key": "v"})
	cMeta.Description = `Download {{url("handout.zip")}} and connect to {{lookup("missing_key")}}.`

	err := m.validateBuild(cMeta, bMeta, []string{"handout.tar.gz"})
	if err == nil {
		t.Fatal("expected the build to fail")
	}

	for _, want := range []string{
		"handout.zip",    // referenced, never produced
		"missing_key",    // referenced, never recorded
		"handout.tar.gz", // produced, never referenced
		"unused_key",     // recorded, never referenced
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("no mention of %q in:\n%s", want, err)
		}
	}
}

// Every bad reference in a single field is reported, not just the last one.
func TestValidateBuildReportsEveryBadReferenceInOneField(t *testing.T) {
	m := newTestManager()
	cMeta, bMeta := buildFixture(nil)
	cMeta.Description = `Take {{url("one.zip")}}, {{url("two.zip")}} and {{url("three.zip")}}.`

	err := m.validateBuild(cMeta, bMeta, nil)
	if err == nil {
		t.Fatal("expected the build to fail")
	}
	for _, want := range []string{"one.zip", "two.zip", "three.zip"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("no mention of %q in:\n%s", want, err)
		}
	}
}

// The unreferenced sweeps range over maps, so the message used to depend on
// map iteration order: the same challenge gave a different error run to run.
// Sorting the keys makes a failure reproducible and diffable.
func TestValidateBuildProblemOrderIsStable(t *testing.T) {
	m := newTestManager()
	published := []string{"delta.zip", "alpha.zip", "charlie.zip", "bravo.zip"}

	cMeta, bMeta := buildFixture(nil)
	first := m.validateBuild(cMeta, bMeta, published)
	if first == nil {
		t.Fatal("expected the unreferenced artifacts to fail the build")
	}

	// Same inputs, fresh maps, many times over: Go deliberately randomizes map
	// iteration, so a dependence on it shows up within a few rounds.
	for i := 0; i < 50; i++ {
		cMeta, bMeta := buildFixture(nil)
		if got := m.validateBuild(cMeta, bMeta, published); got.Error() != first.Error() {
			t.Fatalf("round %d differed:\n first: %s\n   got: %s", i, first, got)
		}
	}

	// Sorted, so alpha is named before bravo before charlie before delta.
	msg := first.Error()
	prev := -1
	for _, name := range []string{"alpha.zip", "bravo.zip", "charlie.zip", "delta.zip"} {
		at := strings.Index(msg, name)
		if at < 0 {
			t.Fatalf("no mention of %q in:\n%s", name, msg)
		}
		if at < prev {
			t.Fatalf("%q is out of order in:\n%s", name, msg)
		}
		prev = at
	}
}

// validateMetadata used to keep only its last problem, so an author with two
// was told about one.
func TestValidateMetadataReportsEveryProblem(t *testing.T) {
	m := newTestManager()
	md := &ChallengeMetadata{
		Id:            ChallengeId("Bad Space/x"),
		Namespace:     "Bad Space",
		ChallengeType: "custom",
		Path:          "/t/problem.md",
		Description:   "A {{server}} reference where it is not allowed.",
	}
	err := m.validateMetadata(md)
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, want := range []string{"missing name", "invalid namespace", "'server' template strings not allowed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%s", want, err)
		}
	}
}
