// Adapted from ArmyCyberInstitute/cmgr at commit bdbf839, under the Apache
// License 2.0. The upstream staged-build rollback test is omitted because this
// fork has not adopted staged builds.
package cmgr

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type artifactTestEntry struct {
	name     string
	typeflag byte
	body     string
	linkname string
}

func artifactTestArchive(t *testing.T, entries []artifactTestEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Mode:     0644,
			Size:     int64(len(entry.body)),
			Linkname: entry.linkname,
		}
		if entry.typeflag == tar.TypeDir || entry.typeflag == tar.TypeSymlink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size != 0 {
			if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestCacheArtifactsValidatesAndInstallsAtomically(t *testing.T) {
	directory := t.TempDir()
	manager := &Manager{
		artifactsDir: directory,
		policy: managerPolicy{
			MaxArtifactFiles:     10,
			MaxArtifactBytes:     1024,
			MaxArtifactFileBytes: 512,
		},
	}
	destination := filepath.Join(directory, "1.tar.gz")
	files, err := manager.cacheArtifacts(
		bytes.NewReader(artifactTestArchive(t, []artifactTestEntry{
			{name: "docs", typeflag: tar.TypeDir},
			{name: "docs/readme.txt", typeflag: tar.TypeReg, body: "hello"},
		})),
		destination,
	)
	if err != nil {
		t.Fatalf("valid archive was rejected: %v", err)
	}
	if len(files) != 1 || files[0] != "docs/readme.txt" {
		t.Fatalf("unexpected artifact list: %#v", files)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("artifact mode is %o, expected 600", info.Mode().Perm())
	}
}

func TestCacheArtifactsRejectsUnsafeOrOversizedArchives(t *testing.T) {
	tests := []struct {
		name    string
		entries []artifactTestEntry
		policy  managerPolicy
		match   string
	}{
		{
			name: "traversal",
			entries: []artifactTestEntry{
				{name: "../escape", typeflag: tar.TypeReg, body: "bad"},
			},
			match: "escapes",
		},
		{
			name: "symlink",
			entries: []artifactTestEntry{
				{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			},
			match: "unsupported tar type",
		},
		{
			name: "entry count",
			entries: []artifactTestEntry{
				{name: "one", typeflag: tar.TypeReg, body: "1"},
				{name: "two", typeflag: tar.TypeReg, body: "2"},
			},
			policy: managerPolicy{
				MaxArtifactFiles:     1,
				MaxArtifactBytes:     100,
				MaxArtifactFileBytes: 100,
			},
			match: "more than 1 entries",
		},
		{
			name: "uncompressed bytes",
			entries: []artifactTestEntry{
				{name: "large", typeflag: tar.TypeReg, body: "12345"},
			},
			policy: managerPolicy{
				MaxArtifactFiles:     10,
				MaxArtifactBytes:     4,
				MaxArtifactFileBytes: 10,
			},
			match: "exceeds 4 uncompressed bytes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			manager := &Manager{artifactsDir: directory, policy: test.policy}
			destination := filepath.Join(directory, "existing.tar.gz")
			if err := os.WriteFile(destination, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := manager.cacheArtifacts(
				bytes.NewReader(artifactTestArchive(t, test.entries)),
				destination,
			)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("unexpected error: %v", err)
			}
			data, readErr := os.ReadFile(destination)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(data) != "original" {
				t.Fatal("failed archive replaced the prior artifact")
			}
		})
	}
}

func TestArtifactDefaultLimitsMatchReleasePolicy(t *testing.T) {
	manager := new(Manager)
	files, total, _ := manager.artifactLimits()
	if files != 10_000 {
		t.Fatalf("default artifact entry limit is %d", files)
	}
	if total != 5*1024*1024*1024 {
		t.Fatalf("default artifact byte limit is %d", total)
	}
}

func TestInitPolicyReadsArtifactLimitsFromEnvironment(t *testing.T) {
	t.Setenv(maxArtifactFilesEnv, "5")
	t.Setenv(maxArtifactBytesEnv, "2m")
	t.Setenv(maxArtifactFileBytesEnv, "512k")

	manager := new(Manager)
	if err := manager.initPolicy(); err != nil {
		t.Fatalf("initPolicy rejected valid limits: %s", err)
	}
	files, total, perFile := manager.artifactLimits()
	if files != 5 {
		t.Fatalf("artifact entry limit is %d; expected 5", files)
	}
	if total != 2*1024*1024 {
		t.Fatalf("artifact byte limit is %d; expected %d", total, 2*1024*1024)
	}
	if perFile != 512*1024 {
		t.Fatalf("per-file byte limit is %d; expected %d", perFile, 512*1024)
	}
}

func TestInitPolicyRejectsInvalidArtifactLimits(t *testing.T) {
	for _, test := range []struct {
		name  string
		key   string
		value string
	}{
		{"zero entries", maxArtifactFilesEnv, "0"},
		{"negative entries", maxArtifactFilesEnv, "-1"},
		{"unparseable entries", maxArtifactFilesEnv, "many"},
		{"zero bytes", maxArtifactBytesEnv, "0"},
		{"unparseable bytes", maxArtifactBytesEnv, "big"},
		{"unparseable per-file bytes", maxArtifactFileBytesEnv, "huge"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			if err := new(Manager).initPolicy(); err == nil {
				t.Fatalf("initPolicy accepted %s=%q", test.key, test.value)
			}
		})
	}
}

// `tar czf artifacts.tar.gz -C dir .` emits a "./" root entry. It is legitimate
// and common, so it must be skipped rather than failing the whole archive.
func TestCacheArtifactsAcceptsTarRootEntry(t *testing.T) {
	directory := t.TempDir()
	manager := &Manager{
		artifactsDir: directory,
		policy: managerPolicy{
			MaxArtifactFiles:     10,
			MaxArtifactBytes:     1024,
			MaxArtifactFileBytes: 1024,
		},
	}
	archive := artifactTestArchive(t, []artifactTestEntry{
		{name: "./", typeflag: tar.TypeDir},
		{name: "./reader", typeflag: tar.TypeReg, body: "x"},
		{name: "notes.txt", typeflag: tar.TypeReg, body: "hi"},
	})
	files, err := manager.cacheArtifacts(bytes.NewReader(archive),
		filepath.Join(directory, "out.tar.gz"))
	if err != nil {
		t.Fatalf("root entry archive was rejected: %s", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %v", files)
	}
}

// artifactLimits' zero-fallbacks must equal the initPolicy defaults, so a
// Manager built either way sees the same bounds.
func TestArtifactZeroFallbacksMatchInitPolicyDefaults(t *testing.T) {
	fallbackFiles, fallbackBytes, fallbackFileBytes := new(Manager).artifactLimits()

	configured := new(Manager)
	if err := configured.initPolicy(); err != nil {
		t.Fatal(err)
	}
	files, total, perFile := configured.artifactLimits()

	if fallbackFiles != files || fallbackBytes != total || fallbackFileBytes != perFile {
		t.Fatalf("zero-fallback limits (%d/%d/%d) differ from initPolicy defaults (%d/%d/%d)",
			fallbackFiles, fallbackBytes, fallbackFileBytes, files, total, perFile)
	}
}

// A literal "./" root entry is skipped but still counted, so a flood of root
// entries cannot slip past CMGR_MAX_ARTIFACT_FILES.
func TestCacheArtifactsCountsSkippedRootEntries(t *testing.T) {
	directory := t.TempDir()
	manager := &Manager{
		artifactsDir: directory,
		policy: managerPolicy{
			MaxArtifactFiles:     3,
			MaxArtifactBytes:     1024,
			MaxArtifactFileBytes: 1024,
		},
	}
	entries := make([]artifactTestEntry, 0, 5)
	for i := 0; i < 5; i++ {
		entries = append(entries, artifactTestEntry{name: "./", typeflag: tar.TypeDir})
	}
	archive := artifactTestArchive(t, entries)
	if _, err := manager.cacheArtifacts(bytes.NewReader(archive),
		filepath.Join(directory, "out.tar.gz")); err == nil {
		t.Fatal("a flood of skipped root entries evaded the entry-count limit")
	}
}

// A directory name that only cleans to "." (e.g. "a/..") is no longer silently
// skipped; it reaches safeArchiveName and is rejected.
func TestCacheArtifactsRejectsCleanedRootDirName(t *testing.T) {
	directory := t.TempDir()
	manager := &Manager{
		artifactsDir: directory,
		policy: managerPolicy{
			MaxArtifactFiles:     10,
			MaxArtifactBytes:     1024,
			MaxArtifactFileBytes: 1024,
		},
	}
	archive := artifactTestArchive(t, []artifactTestEntry{
		{name: "a/..", typeflag: tar.TypeDir},
	})
	if _, err := manager.cacheArtifacts(bytes.NewReader(archive),
		filepath.Join(directory, "out.tar.gz")); err == nil {
		t.Fatal("a non-literal root dir name 'a/..' was silently accepted")
	}
}

// A raw name longer than the path bound is rejected even when path.Clean
// collapses it to a short name.
func TestCacheArtifactsRejectsOverlongRawName(t *testing.T) {
	directory := t.TempDir()
	manager := &Manager{
		artifactsDir: directory,
		policy: managerPolicy{
			MaxArtifactFiles:     10,
			MaxArtifactBytes:     1 << 20,
			MaxArtifactFileBytes: 1 << 20,
		},
	}
	longName := strings.Repeat("./", 5000) + "realfile" // cleans to "realfile"
	archive := artifactTestArchive(t, []artifactTestEntry{
		{name: longName, typeflag: tar.TypeReg, body: "x"},
	})
	if _, err := manager.cacheArtifacts(bytes.NewReader(archive),
		filepath.Join(directory, "out.tar.gz")); err == nil {
		t.Fatalf("an oversized raw name (%d bytes) was accepted", len(longName))
	}
}

func TestBoundedReaderCapsTotalBytes(t *testing.T) {
	src := bytes.NewReader(make([]byte, 10000))
	b := &boundedReader{reader: src, remaining: 4096}
	n, err := io.Copy(io.Discard, b)
	if err == nil {
		t.Fatalf("boundedReader did not error after its limit (read %d bytes)", n)
	}
	if n > 4096 {
		t.Fatalf("boundedReader passed %d bytes past its 4096 limit", n)
	}
}

// tar.Reader.Next consumes GNU long-name / PAX records internally, so their
// decompressed bytes never reach entryCount or totalBytes. A metadata flood
// must therefore be caught by the aggregate decompressed-stream bound, not the
// per-entry limits.
func TestCacheArtifactsBoundsUncountedMetadata(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for i := 0; i < 20; i++ {
		// A 200KB name forces a GNU long-name record Next() reads internally.
		name := strings.Repeat("a", 200000) + fmt.Sprintf("%d", i)
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Size: 1, Format: tar.FormatGNU,
		}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte("x"))
	}
	tw.Close()
	gz.Close()

	directory := t.TempDir()
	// Budget = maxBytes + maxFiles*8KB + slack ~= 85KB, below a single 200KB
	// long-name record, so the bound fires while reading metadata — before the
	// oversized name would even surface to safeArchiveName.
	manager := &Manager{
		artifactsDir: directory,
		policy: managerPolicy{
			MaxArtifactFiles:     10,
			MaxArtifactBytes:     1024,
			MaxArtifactFileBytes: 1024,
		},
	}
	_, err := manager.cacheArtifacts(bytes.NewReader(raw.Bytes()),
		filepath.Join(directory, "out.tar.gz"))
	if err == nil {
		t.Fatal("metadata-record flood was not bounded")
	}
	if !strings.Contains(err.Error(), "decompresses beyond") {
		t.Fatalf("expected the decompressed-size bound to fire, got: %s", err)
	}
}

// stageArchive writes content where executeBuild would stage the build's
// archive and records it on the build.
func stageArchive(t *testing.T, m *Manager, build *BuildMetadata, content string) {
	t.Helper()
	build.stagedArtifacts = filepath.Join(m.artifactsDir, "."+build.getArtifactsFilename()+".staged")
	if err := os.WriteFile(build.stagedArtifacts, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readServed(t *testing.T, m *Manager, build *BuildMetadata) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.artifactsDir, build.getArtifactsFilename()))
	if os.IsNotExist(err) {
		return "<none>"
	} else if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The archive a build is served from changes only when its row is recorded:
// promoted after finalizeBuild, discarded when the build is not recorded.
func TestStagedArtifactsPromoteOrDiscard(t *testing.T) {
	m := &Manager{log: newLogger(DISABLED), artifactsDir: t.TempDir()}
	build := &BuildMetadata{Id: 7, Challenge: "test/artifacts"}

	stageArchive(t, m, build, "generation 1")
	if got := readServed(t, m, build); got != "<none>" {
		t.Fatalf("a staged archive is served before promotion: %q", got)
	}
	if err := m.promoteArtifacts(build); err != nil {
		t.Fatal(err)
	}
	if got := readServed(t, m, build); got != "generation 1" {
		t.Fatalf("served %q after promotion, want generation 1", got)
	}

	stageArchive(t, m, build, "generation 2")
	staged := build.stagedArtifacts
	m.discardArtifacts(build)
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("the discarded archive is still on disk: %v", err)
	}
	if got := readServed(t, m, build); got != "generation 1" {
		t.Fatalf("served %q after a discard, want generation 1 untouched", got)
	}
}

// A rebuild that publishes no archive any more must not leave the previous
// generation's archive behind to be served under the build's id.
func TestPromoteArtifactsRemovesADroppedArchive(t *testing.T) {
	m := &Manager{log: newLogger(DISABLED), artifactsDir: t.TempDir()}
	build := &BuildMetadata{Id: 8, Challenge: "test/artifacts"}

	stageArchive(t, m, build, "generation 1")
	if err := m.promoteArtifacts(build); err != nil {
		t.Fatal(err)
	}
	// The next generation produced no archive: nothing was staged.
	if err := m.promoteArtifacts(build); err != nil {
		t.Fatal(err)
	}
	if got := readServed(t, m, build); got != "<none>" {
		t.Fatalf("served %q after a rebuild without artifacts, want nothing", got)
	}
	// And a build that never had one is not an error.
	if err := m.promoteArtifacts(build); err != nil {
		t.Fatalf("promoting nothing over nothing failed: %s", err)
	}
}
