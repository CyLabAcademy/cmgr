// The per-challenge seccomp profile handling in this file is adapted from
// ArmyCyberInstitute/cmgr at commit a5a3bda:
// https://github.com/ArmyCyberInstitute/cmgr
//
// The original project is available under the Apache License 2.0. This file is
// a reduced implementation for this fork, also distributed under cmgr's Apache
// License 2.0. Upstream additionally supports a `legacy` mode and named
// `tweaks` applied through an OCI runtime interceptor. Neither is adopted here:
// this fork already applies the historical cmgr profile by default, so `legacy`
// would be a no-op, and a complete profile does not require a runtime
// interceptor because Docker accepts one directly.
package cmgr

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxSeccompProfileSize bounds how much of a challenge-supplied profile cmgr
// will read. Docker's own default profile is well under 200KB.
const maxSeccompProfileSize = 1024 * 1024

type seccompArgument struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

type seccompSyscall struct {
	Name     string            `json:"name,omitempty"`
	Names    []string          `json:"names"`
	Action   string            `json:"action"`
	ErrnoRet *uint             `json:"errnoRet,omitempty"`
	Args     []seccompArgument `json:"args,omitempty"`
}

type seccompProfile struct {
	DefaultAction   string           `json:"defaultAction"`
	DefaultErrnoRet *uint            `json:"defaultErrnoRet,omitempty"`
	Syscalls        []seccompSyscall `json:"syscalls"`
}

// resolve loads and validates a challenge's seccomp profile, if it declares
// one. A challenge that declares no profile keeps cmgr's embedded policy, so an
// empty SeccompOptions is the documented no-op.
func (opts *SeccompOptions) resolve(challengeDir string) error {
	opts.ProfileHash = ""
	opts.effectiveProfile = ""

	if opts.Profile == "" {
		return nil
	}

	profile, err := readSeccompProfile(challengeDir, opts.Profile)
	if err != nil {
		return err
	}
	if err = validateSeccompProfile(profile); err != nil {
		return err
	}

	sum := sha256.Sum256([]byte(profile))
	opts.ProfileHash = fmt.Sprintf("%x", sum)
	opts.effectiveProfile = profile
	return nil
}

// seccompSecurityOpt passes profile to Docker as a security option. Docker
// splits an option at its first '=' when it has one, so the ':' form breaks on
// any profile containing '='.
func seccompSecurityOpt(profile string) string {
	return "seccomp=" + profile
}

// validateSeccompProfileFilename constrains profiles to a plain JSON file
// beside the challenge metadata. Names beginning with '.' are rejected in
// particular because checksumIgnore skips them, so a hidden profile would not
// contribute to the challenge's source checksum and edits to it would not
// trigger a rebuild.
func validateSeccompProfileFilename(profilePath string) error {
	if profilePath == "" {
		return fmt.Errorf("seccomp profile filename cannot be empty")
	}
	if filepath.IsAbs(profilePath) || filepath.Base(profilePath) != profilePath {
		return fmt.Errorf("seccomp profile must be a JSON file in the challenge directory")
	}
	if profilePath[0] == '.' {
		return fmt.Errorf("seccomp profile filename must not start with '.'")
	}
	if filepath.Ext(profilePath) != ".json" {
		return fmt.Errorf("seccomp profile filename must end with '.json'")
	}
	// problem.json/problem.md are the challenge's own metadata; metadata.json is
	// the build-output metadata cmgr generates and reads back. None can double as
	// a profile without colliding with a file cmgr already owns.
	if profilePath == "problem.json" || profilePath == "problem.md" || profilePath == "metadata.json" {
		return fmt.Errorf("%s cannot also be used as a seccomp profile", profilePath)
	}
	for _, character := range profilePath {
		isLetter := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z'
		isNumber := character >= '0' && character <= '9'
		if !isLetter && !isNumber &&
			character != '_' && character != '-' && character != '.' {
			return fmt.Errorf(
				"seccomp profile filename %q contains unsupported characters",
				profilePath,
			)
		}
	}
	return nil
}

func readSeccompProfile(challengeDir, profilePath string) (string, error) {
	if err := validateSeccompProfileFilename(profilePath); err != nil {
		return "", err
	}

	root, err := filepath.Abs(challengeDir)
	if err != nil {
		return "", fmt.Errorf("could not resolve challenge directory for seccomp profile: %s", err)
	}
	candidate := filepath.Join(root, profilePath)
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", fmt.Errorf("could not inspect seccomp profile '%s': %s", profilePath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("seccomp profile '%s' must not be a symbolic link", profilePath)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("seccomp profile '%s' is not a regular file", profilePath)
	}
	if info.Size() > maxSeccompProfileSize {
		return "", fmt.Errorf("seccomp profile '%s' exceeds the %d byte size limit", profilePath, maxSeccompProfileSize)
	}

	file, err := os.Open(candidate)
	if err != nil {
		return "", fmt.Errorf("could not open seccomp profile '%s': %s", profilePath, err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("could not inspect open seccomp profile '%s': %s", profilePath, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return "", fmt.Errorf("seccomp profile '%s' changed while it was being opened", profilePath)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxSeccompProfileSize+1))
	if err != nil {
		return "", fmt.Errorf("could not read seccomp profile '%s': %s", profilePath, err)
	}
	if len(data) > maxSeccompProfileSize {
		return "", fmt.Errorf("seccomp profile '%s' exceeds the %d byte size limit", profilePath, maxSeccompProfileSize)
	}
	return string(data), nil
}

// validSeccompActions and validSeccompOperators are the action and argument
// operator enums defined by the OCI runtime spec. Docker checks a profile
// against these when it creates a container; checking them here as well means a
// typo such as SCMP_ACT_ALOW is rejected during challenge validation, when the
// author can see it, rather than surfacing only when the first runtime container
// fails to launch. Keep these in sync with the spec if it grows new values.
var validSeccompActions = map[string]bool{
	"SCMP_ACT_KILL":         true,
	"SCMP_ACT_KILL_PROCESS": true,
	"SCMP_ACT_KILL_THREAD":  true,
	"SCMP_ACT_TRAP":         true,
	"SCMP_ACT_ERRNO":        true,
	"SCMP_ACT_TRACE":        true,
	"SCMP_ACT_ALLOW":        true,
	"SCMP_ACT_LOG":          true,
	"SCMP_ACT_NOTIFY":       true,
}

var validSeccompOperators = map[string]bool{
	"SCMP_CMP_NE":        true,
	"SCMP_CMP_LT":        true,
	"SCMP_CMP_LE":        true,
	"SCMP_CMP_EQ":        true,
	"SCMP_CMP_GE":        true,
	"SCMP_CMP_GT":        true,
	"SCMP_CMP_MASKED_EQ": true,
}

func validateSeccompProfile(profile string) error {
	var document seccompProfile
	if err := json.Unmarshal([]byte(profile), &document); err != nil {
		return fmt.Errorf("invalid seccomp profile JSON: %s", err)
	}
	if document.DefaultAction == "" {
		return fmt.Errorf("invalid seccomp profile: defaultAction must be a non-empty string")
	}
	if !validSeccompActions[document.DefaultAction] {
		return fmt.Errorf("invalid seccomp profile: unknown defaultAction %q", document.DefaultAction)
	}
	for i, syscall := range document.Syscalls {
		if syscall.Name != "" && len(syscall.Names) != 0 {
			return fmt.Errorf("invalid seccomp profile: syscall rule %d specifies both name and names", i)
		}
		if syscall.Name == "" && len(syscall.Names) == 0 {
			return fmt.Errorf("invalid seccomp profile: syscall rule %d does not specify any names", i)
		}
		if syscall.Action == "" {
			return fmt.Errorf("invalid seccomp profile: syscall rule %d does not specify an action", i)
		}
		if !validSeccompActions[syscall.Action] {
			return fmt.Errorf("invalid seccomp profile: syscall rule %d has unknown action %q", i, syscall.Action)
		}
		for j, argument := range syscall.Args {
			if argument.Op == "" {
				return fmt.Errorf("invalid seccomp profile: argument %d in syscall rule %d does not specify an operator", j, i)
			}
			if !validSeccompOperators[argument.Op] {
				return fmt.Errorf("invalid seccomp profile: argument %d in syscall rule %d has unknown operator %q", j, i, argument.Op)
			}
		}
	}
	return nil
}

// persistedSeccompOptions carries the resolved profile text alongside the
// challenge's declaration. effectiveProfile is unexported and so does not
// survive a plain round trip through the database, but container launch needs
// it long after the challenge directory was last read.
type persistedSeccompOptions struct {
	Options          *SeccompOptions `json:"options,omitempty"`
	EffectiveProfile string          `json:"effective_profile,omitempty"`
}

func marshalSeccompOptions(opts *SeccompOptions) (string, error) {
	if opts == nil || (opts.Profile == "" && opts.effectiveProfile == "") {
		return "", nil
	}
	data, err := json.Marshal(persistedSeccompOptions{
		Options:          opts,
		EffectiveProfile: opts.effectiveProfile,
	})
	if err != nil {
		return "", fmt.Errorf("could not encode seccomp options: %s", err)
	}
	return string(data), nil
}

func unmarshalSeccompOptions(data string) (*SeccompOptions, error) {
	if data == "" {
		return nil, nil
	}
	var persisted persistedSeccompOptions
	if err := json.Unmarshal([]byte(data), &persisted); err != nil {
		return nil, fmt.Errorf("could not decode seccomp options: %s", err)
	}
	if persisted.Options == nil {
		return nil, nil
	}
	persisted.Options.effectiveProfile = persisted.EffectiveProfile
	return persisted.Options, nil
}
