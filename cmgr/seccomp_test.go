package cmgr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const testSeccompProfile = `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0, "value": 18446744073704964087, "op": "SCMP_CMP_MASKED_EQ"}]
    }
  ]
}`

func writeProfile(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveWithoutProfileKeepsEmbeddedPolicy(t *testing.T) {
	options := &SeccompOptions{}
	if err := options.resolve(t.TempDir()); err != nil {
		t.Fatalf("empty options were rejected: %s", err)
	}
	if options.effectiveProfile != "" || options.ProfileHash != "" {
		t.Fatalf("empty options resolved to a profile: %#v", options)
	}
}

func TestResolveLoadsHashesAndIsStable(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, "execstack.json", testSeccompProfile)

	options := &SeccompOptions{Profile: "execstack.json"}
	if err := options.resolve(dir); err != nil {
		t.Fatalf("valid profile was rejected: %s", err)
	}
	if options.effectiveProfile != testSeccompProfile {
		t.Fatalf("effective profile does not match the file on disk")
	}
	if len(options.ProfileHash) != 64 {
		t.Fatalf("profile hash is %q; expected a sha256 hex digest", options.ProfileHash)
	}

	// A different profile must produce a different hash, so that editing a
	// profile is distinguishable from leaving it alone.
	other := &SeccompOptions{Profile: "other.json"}
	writeProfile(t, dir, "other.json", strings.Replace(testSeccompProfile, "ERRNO", "KILL", 1))
	if err := other.resolve(dir); err != nil {
		t.Fatal(err)
	}
	if other.ProfileHash == options.ProfileHash {
		t.Fatalf("distinct profiles produced the same hash")
	}
}

func TestResolveRejectsUnsafeProfileReferences(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, "good.json", testSeccompProfile)
	writeProfile(t, dir, "problem.json", testSeccompProfile)
	writeProfile(t, dir, "notjson.txt", testSeccompProfile)
	writeProfile(t, dir, "bad.json", "{not json")
	writeProfile(t, dir, "noaction.json", `{"defaultAction": ""}`)
	writeProfile(t, dir, "norule.json",
		`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"action":"SCMP_ACT_ALLOW"}]}`)
	writeProfile(t, dir, "metadata.json", testSeccompProfile)
	writeProfile(t, dir, "badaction.json", `{"defaultAction":"SCMP_ACT_ALOW"}`)
	writeProfile(t, dir, "badsyscallaction.json",
		`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALOW"}]}`)
	writeProfile(t, dir, "badoperator.json",
		`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_BOGUS"}]}]}`)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	writeProfile(t, dir, filepath.Join("sub", "nested.json"), testSeccompProfile)

	for _, test := range []struct{ name, profile string }{
		{"traversal", "../escape.json"},
		{"subdirectory", "sub/nested.json"},
		{"absolute", filepath.Join(dir, "good.json")},
		{"hidden", ".hidden.json"},
		{"wrong extension", "notjson.txt"},
		{"challenge metadata json", "problem.json"},
		{"challenge metadata markdown", "problem.md"},
		{"challenge build metadata", "metadata.json"},
		{"unsupported characters", "pro file.json"},
		{"missing", "absent.json"},
		{"directory", "sub"},
		{"malformed json", "bad.json"},
		{"empty default action", "noaction.json"},
		{"unknown default action", "badaction.json"},
		{"unknown syscall action", "badsyscallaction.json"},
		{"unknown argument operator", "badoperator.json"},
		{"rule without names", "norule.json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := &SeccompOptions{Profile: test.profile}
			if err := options.resolve(dir); err == nil {
				t.Fatalf("resolve accepted profile %q", test.profile)
			}
		})
	}
}

// The effective profile is unexported, so a plain JSON round trip would drop
// it and containers would silently fall back to the embedded policy.
func TestSeccompOptionsSurviveDatabaseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, "execstack.json", testSeccompProfile)

	options := &SeccompOptions{Profile: "execstack.json"}
	if err := options.resolve(dir); err != nil {
		t.Fatal(err)
	}

	encoded, err := marshalSeccompOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" {
		t.Fatal("resolved options encoded to an empty column value")
	}

	decoded, err := unmarshalSeccompOptions(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded == nil {
		t.Fatal("decoded options are nil")
	}
	if decoded.Profile != options.Profile {
		t.Fatalf("profile name is %q; expected %q", decoded.Profile, options.Profile)
	}
	if decoded.ProfileHash != options.ProfileHash {
		t.Fatalf("profile hash is %q; expected %q", decoded.ProfileHash, options.ProfileHash)
	}
	if decoded.effectiveProfile != testSeccompProfile {
		t.Fatalf("effective profile did not survive the round trip")
	}
}

func TestMarshalSeccompOptionsSkipsUnusedOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		options *SeccompOptions
	}{
		{"nil", nil},
		{"empty", &SeccompOptions{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := marshalSeccompOptions(test.options)
			if err != nil {
				t.Fatal(err)
			}
			if encoded != "" {
				t.Fatalf("unused options encoded to %q; expected an empty column", encoded)
			}
			decoded, err := unmarshalSeccompOptions(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != nil {
				t.Fatalf("empty column decoded to %#v; expected nil", decoded)
			}
		})
	}
}

// The embedded policy must stay parseable by the same validator applied to
// challenge-supplied profiles, since it is the fallback for every container.
func TestEmbeddedPolicyPassesProfileValidation(t *testing.T) {
	if err := validateSeccompProfile(seccompPolicy); err != nil {
		t.Fatalf("embedded seccomp policy failed validation: %s", err)
	}
	var document seccompProfile
	if err := json.Unmarshal([]byte(seccompPolicy), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Syscalls) == 0 {
		t.Fatal("embedded seccomp policy declares no syscall rules")
	}
}

// A per-syscall "comment" is valid Docker profile syntax that validation
// ignores, so an '=' in one reaches the security option and must not move
// where Docker splits it.
func TestSeccompSecurityOptKeepsProfileWithEquals(t *testing.T) {
	profile := strings.Replace(testSeccompProfile, `"action"`, `"comment": "persona=0xffffffff only queries", "action"`, 1)
	if err := validateSeccompProfile(profile); err != nil {
		t.Fatalf("profile with a comment was rejected: %s", err)
	}
	// Docker's parseSecurityOpt cuts at the first '=' whenever there is one.
	key, value, _ := strings.Cut(seccompSecurityOpt(profile), "=")
	if key != "seccomp" || value != profile {
		t.Fatalf("security option splits into key %q and a %d-byte value; expected seccomp and the %d-byte profile", key, len(value), len(profile))
	}
}

// Challenge options arrive as JSON from problem.json and as YAML from
// problem.md, so the option must decode through both paths.
func TestSeccompOptionParsesFromChallengeMetadata(t *testing.T) {
	var fromJSON ChallengeOptions
	if err := json.Unmarshal(
		[]byte(`{"cpus":"0.5","seccomp":{"profile":"execstack.json"}}`),
		&fromJSON,
	); err != nil {
		t.Fatalf("problem.json options rejected: %s", err)
	}
	if fromJSON.Seccomp == nil || fromJSON.Seccomp.Profile != "execstack.json" {
		t.Fatalf("seccomp option did not decode from JSON: %#v", fromJSON.Seccomp)
	}

	var fromYAML ChallengeOptions
	if err := yaml.Unmarshal(
		[]byte("cpus: \"0.5\"\nseccomp:\n    profile: execstack.json\n"),
		&fromYAML,
	); err != nil {
		t.Fatalf("problem.md options rejected: %s", err)
	}
	if fromYAML.Seccomp == nil || fromYAML.Seccomp.Profile != "execstack.json" {
		t.Fatalf("seccomp option did not decode from YAML: %#v", fromYAML.Seccomp)
	}

	// A challenge that declares no seccomp block must stay on the embedded
	// policy rather than decoding to a non-nil, empty override.
	var bare ChallengeOptions
	if err := yaml.Unmarshal([]byte("cpus: \"0.5\"\n"), &bare); err != nil {
		t.Fatal(err)
	}
	if bare.Seccomp != nil {
		t.Fatalf("absent seccomp block decoded to %#v", bare.Seccomp)
	}
}

// The shipped example profiles are the copy-paste starting point for challenge
// authors, so they must stay loadable by the same code that loads a
// challenge's. This catches a malformed edit and catches an example drifting
// out of sync with the validator.
func TestExampleProfilesAreValid(t *testing.T) {
	// Only the profile library is globbed. The execstack challenge directory is
	// intentionally excluded: building it with `make` generates non-profile JSON
	// (metadata.json), which is not a seccomp profile and would fail validation
	// here after a developer builds the example. Its execstack.json copy is
	// covered instead by TestExecstackExampleMatchesLibraryProfile, which proves
	// it is byte-identical to the library profile validated below.
	dirs := []string{
		filepath.Join("..", "examples", "seccomp"),
	}
	found := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("could not read example profiles in %s: %s", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			found++
			t.Run(entry.Name(), func(t *testing.T) {
				if err := validateSeccompProfileFilename(entry.Name()); err != nil {
					t.Fatalf("example filename is not usable as a profile: %s", err)
				}
				options := &SeccompOptions{Profile: entry.Name()}
				if err := options.resolve(dir); err != nil {
					t.Fatalf("example profile did not resolve: %s", err)
				}
				if options.effectiveProfile == "" || options.ProfileHash == "" {
					t.Fatal("example profile resolved to an empty policy")
				}
				// default.json is the pristine baseline authors copy to make
				// their own edits (and profile-diff.py's fallback baseline
				// outside a cmgr checkout), so it must track the embedded
				// policy exactly. Every other example is the embedded policy
				// plus a delta, so it must differ.
				if entry.Name() == "default.json" {
					if options.effectiveProfile != seccompPolicy {
						t.Fatal("examples/seccomp/default.json has drifted from the embedded cmgr/seccomp.json")
					}
					return
				}
				if options.effectiveProfile == seccompPolicy {
					t.Fatal("example profile is identical to the embedded policy")
				}
			})
		}
	}
	if found == 0 {
		t.Fatal("no example seccomp profiles found")
	}
}

// The execstack worked-example challenge ships its own copy of the profile
// because a profile must live beside problem.md. Keep that copy identical to
// the library example so the two do not drift.
func TestExecstackExampleMatchesLibraryProfile(t *testing.T) {
	library, err := os.ReadFile(filepath.Join("..", "examples", "seccomp", "execstack.json"))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := os.ReadFile(filepath.Join("..", "examples", "execstack", "execstack.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(library) != string(challenge) {
		t.Fatal("examples/execstack/execstack.json has drifted from examples/seccomp/execstack.json")
	}
}
