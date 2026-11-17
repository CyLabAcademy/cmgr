package cmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jmoiron/sqlx"
)

// Columns for list/search results: the light-weight subset plus what
// deriveDeliveryType needs (challenge type + published port count), so every
// ChallengeMetadata leaving these paths carries a valid delivery type.
const listChallengeColumns = `id, name, path, sourcechecksum, metadatachecksum, solvescript, challengetype,
	(SELECT COUNT(*) FROM portNames WHERE portNames.challenge = challenges.id) AS portcount`

type listChallengeRow struct {
	ChallengeMetadata
	PortCount int `db:"portcount"`
}

func listRowsToMetadata(rows []listChallengeRow) []*ChallengeMetadata {
	metadata := make([]*ChallengeMetadata, len(rows))
	for i := range rows {
		md := rows[i].ChallengeMetadata
		md.DeliveryType = deriveDeliveryType(md.ChallengeType, rows[i].PortCount)
		metadata[i] = &md
	}
	return metadata
}

// Gets just the ID and checksum for all known challenges
func (m *Manager) listChallenges() ([]*ChallengeMetadata, error) {
	rows := []listChallengeRow{}
	err := m.db.Select(&rows, "SELECT "+listChallengeColumns+" FROM challenges ORDER BY id;")
	return listRowsToMetadata(rows), err
}

func (m *Manager) searchChallenges(tags []string) ([]*ChallengeMetadata, error) {
	if len(tags) == 0 {
		return m.listChallenges()
	}

	interfaceTags := make([]interface{}, len(tags))
	for i, tag := range tags {
		interfaceTags[i] = strings.ReplaceAll(tag, "*", "%")
	}
	tagBaseQuery := "SELECT challenge FROM tags WHERE tag LIKE ?"
	subQuery := "(" +
		tagBaseQuery +
		strings.Repeat(" INTERSECT "+tagBaseQuery, len(tags)-1) +
		")"
	query := fmt.Sprintf("SELECT %s FROM challenges WHERE id IN %s ORDER BY id;", listChallengeColumns, subQuery)
	rows := []listChallengeRow{}
	err := m.db.Select(&rows, query, interfaceTags...)

	return listRowsToMetadata(rows), err
}

func (m *Manager) lookupChallengeMetadata(challenge ChallengeId) (*ChallengeMetadata, error) {
	metadata := new(ChallengeMetadata)
	txn := m.db.MustBegin()

	err := txn.Get(metadata, "SELECT * FROM challenges WHERE id=?", challenge)
	if isEmptyQueryError(err) {
		err = unknownChallengeIdError(challenge)
	}

	if err == nil {
		err = txn.Select(&metadata.Hints, "SELECT hint FROM hints WHERE challenge=? ORDER BY idx", challenge)
	}

	if err == nil {
		err = txn.Select(&metadata.Tags, "SELECT tag FROM tags WHERE challenge=?", challenge)
	}

	if err == nil {
		err = txn.Select(&metadata.Hosts, "SELECT name, target FROM hosts WHERE challenge=?", challenge)
	}

	ports := []struct {
		Name string
		Host string
		Port int
	}{}
	if err == nil {
		err = txn.Select(&ports, "SELECT name, host, port FROM portNames WHERE challenge=?", challenge)
	}

	metadata.PortMap = make(map[string]PortInfo)
	for _, port := range ports {
		metadata.PortMap[port.Name] = PortInfo{port.Host, port.Port}
	}

	// Derived from the same port data exposed as PortMap (plus the challenge
	// type) so the reported delivery type can never disagree with the
	// instance-launch decision that reads it.
	metadata.DeliveryType = deriveDeliveryType(metadata.ChallengeType, len(metadata.PortMap))

	attributes := []struct {
		Key   string
		Value string
	}{}
	if err == nil {
		err = txn.Select(&attributes, "SELECT key, value FROM attributes WHERE challenge=?", challenge)
	}

	metadata.Attributes = make(map[string]string)
	for _, attr := range attributes {
		metadata.Attributes[attr.Key] = attr.Value
	}

	networkOptions := new(NetworkOptions)
	// Note: there are currently no network-level challenge options, but they will be loaded here if added in the future.

	// if err == nil {
	// 	err = txn.Get(networkOptions, "SELECT '' FROM networkOptions WHERE challenge=?", challenge)
	// }
	metadata.ChallengeOptions.NetworkOptions = *networkOptions

	containerOptions := new([]dbContainerOptions)
	if err == nil {
		err = txn.Select(containerOptions, "SELECT host, init, cpus, memory, ulimits, pidslimit, readonlyrootfs, droppedcaps, nonewprivileges, diskquota, cgroupparent, capimmutable, seccomp FROM containerOptions WHERE challenge=?", challenge)
	}
	for _, dbOpts := range *containerOptions {
		var cOpts ContainerOptions
		cOpts, err = newFromDbContainerOptions(dbOpts)
		if err != nil {
			m.log.errorf("could not decode container options for '%s' (host '%s'): %s", challenge, dbOpts.Host, err)
			break
		}
		if metadata.ChallengeOptions.Overrides == nil {
			metadata.ChallengeOptions.Overrides = make(map[string]ContainerOptions)
		}
		metadata.ChallengeOptions.Overrides[dbOpts.Host] = cOpts
	}
	metadata.ChallengeOptions.ContainerOptions = metadata.ChallengeOptions.Overrides[""]

	if err == nil {
		err = txn.Commit()
		if err != nil {
			m.log.errorf("failed to commit read-only transaction: %s", err)
		}
	} else {
		m.log.errorf("read of database failed: %s", err)
		closeErr := txn.Rollback()
		if closeErr != nil {
			m.log.errorf("rollback failed: %s", err)
			err = closeErr
		}
	}

	return metadata, err
}

// Adds the discovered challenges to the database
func (m *Manager) addChallenges(addedChallenges []*ChallengeMetadata) []error {
	errs := []error{}
	for _, metadata := range addedChallenges {
		if err := m.writeChallenge(metadata, challengeInsertQuery); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// writeChallenge records a challenge and the rows that hang off it in one
// transaction, query inserting or updating the challenge row itself. The
// first failure rolls the whole write back and is the error returned.
func (m *Manager) writeChallenge(metadata *ChallengeMetadata, query string) error {
	txn, err := m.db.Beginx()
	if err != nil {
		m.log.error(err)
		return err
	}
	if err = m.writeChallengeRows(txn, metadata, query); err != nil {
		err = fmt.Errorf("could not record challenge %s: %w", metadata.Id, err)
		m.log.error(err)
		if rbErr := txn.Rollback(); rbErr != nil {
			m.log.error(rbErr)
		}
		return err
	}
	if err = txn.Commit(); err != nil {
		m.log.error(err)
	}
	return err
}

func (m *Manager) writeChallengeRows(txn *sqlx.Tx, metadata *ChallengeMetadata, query string) error {
	if _, err := txn.NamedExec(query, metadata); err != nil {
		return err
	}
	// There are no network-level challenge options yet; they would go here.
	for _, table := range []string{"hints", "tags", "attributes", "hosts", "portNames", "containerOptions"} {
		if _, err := txn.Exec("DELETE FROM "+table+" WHERE challenge = ?;", metadata.Id); err != nil {
			return err
		}
	}
	for i, hint := range metadata.Hints {
		if _, err := txn.Exec("INSERT INTO hints(challenge, idx, hint) VALUES (?, ?, ?);",
			metadata.Id, i, hint); err != nil {
			return err
		}
	}
	for _, tag := range metadata.Tags {
		if _, err := txn.Exec("INSERT INTO tags(challenge, tag) VALUES (?, ?);",
			metadata.Id, tag); err != nil {
			return err
		}
	}
	for k, v := range metadata.Attributes {
		if _, err := txn.Exec("INSERT INTO attributes(challenge, key, value) VALUES (?, ?, ?);",
			metadata.Id, k, v); err != nil {
			return err
		}
	}
	for i, host := range metadata.Hosts {
		m.log.debugf("%s: %v", metadata.Id, host)
		if _, err := txn.Exec("INSERT INTO hosts(challenge, name, idx, target) VALUES (?, ?, ?, ?);",
			metadata.Id, host.Name, i, host.Target); err != nil {
			return err
		}
	}
	for k, v := range metadata.PortMap {
		m.log.debugf("%s: %v", metadata.Id, v)
		if _, err := txn.Exec("INSERT INTO portNames(challenge, name, host, port) VALUES (?, ?, ?, ?);",
			metadata.Id, k, v.Host, v.Port); err != nil {
			return err
		}
	}
	for host, opts := range metadata.ChallengeOptions.Overrides {
		dbOpts, err := opts.toDbContainerOptions()
		if err != nil {
			return err
		}
		m.log.debugf("%s (host %q): %v", metadata.Id, host, dbOpts)
		if _, err = txn.Exec("INSERT INTO containerOptions(challenge, host, init, cpus, memory, ulimits, pidslimit, readonlyrootfs, droppedcaps, nonewprivileges, diskquota, cgroupparent, capimmutable, seccomp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
			metadata.Id,
			host,
			dbOpts.Init,
			dbOpts.Cpus,
			dbOpts.Memory,
			dbOpts.Ulimits,
			dbOpts.PidsLimit,
			dbOpts.ReadonlyRootfs,
			dbOpts.DroppedCaps,
			dbOpts.NoNewPrivileges,
			dbOpts.DiskQuota,
			dbOpts.CgroupParent,
			dbOpts.CapImmutable,
			dbOpts.Seccomp); err != nil {
			return err
		}
	}
	return nil
}

// rotatedPrevChecksum returns the rollback generation to retain after a
// rebuild. When the content changed (newChecksum != oldChecksum) the generation
// just replaced (oldChecksum) becomes the new rollback target; otherwise the
// existing target (currentPrev) is left untouched, so a no-op rebuild does not
// disturb retention.
func rotatedPrevChecksum(oldChecksum, newChecksum, currentPrev uint32) uint32 {
	if newChecksum != oldChecksum {
		return oldChecksum
	}
	return currentPrev
}

// displacedPruneCandidate reports whether a rebuild displaced an image
// generation that '--prune-old' should untag: the content actually changed
// (newChecksum != oldChecksum), there was a prior rollback generation to
// displace (displaced != 0), and that displaced generation is not the same
// content as the just-rebuilt one. The last clause guards an A->B->A
// flip-flop, where the displaced generation equals the new current generation
// and must therefore be kept, not pruned.
func displacedPruneCandidate(oldChecksum, newChecksum, displaced uint32) bool {
	return newChecksum != oldChecksum && displaced != 0 && displaced != newChecksum
}

func (m *Manager) updateChallenges(updatedChallenges []*ChallengeMetadata, rebuild bool, pruneOldImages bool) []error {
	errs := []error{}
	for _, metadata := range updatedChallenges {
		err := m.writeChallenge(metadata, challengeUpdateQuery)
		if err != nil {
			errs = append(errs, err)
			continue // next challenge
		}

		if rebuild {
			buildIds := []BuildId{}
			err = m.db.Select(&buildIds, "SELECT id FROM builds WHERE challenge=?;", metadata.Id)
			if err != nil {
				m.log.error(err)
				errs = append(errs, err)
				continue
			}

			if len(buildIds) > 0 {
				buildCtxFile, err := m.createBuildContext(metadata, m.GetDockerfile(metadata.ChallengeType))
				if err != nil {
					m.log.errorf("failed to create build context: %s", err)
					errs = append(errs, err)
					continue
				}
				defer os.Remove(buildCtxFile)

				replaced := []replacedImages{}
				for _, buildId := range buildIds {
					build, err := m.lookupBuildMetadata(buildId)
					if err != nil {
						errs = append(errs, err)
						continue
					}
					cMeta, err := m.lookupChallengeMetadata(build.Challenge)
					if err != nil {
						errs = append(errs, err)
						continue
					}

					// Capture the retention pair before executeBuild stamps the
					// new content checksum: the current generation becomes the
					// retained rollback target (PrevChecksum) and the old
					// rollback generation is displaced from retention.
					oldChecksum := build.Checksum
					displaced := build.PrevChecksum

					// Resetting the flag signals to rebuild the Dockerfile
					build.Flag = ""
					err = m.executeBuild(metadata, build, buildCtxFile)
					if err != nil {
						errs = append(errs, err)
						continue
					}

					// Rotate the retention pair; a rebuild that reproduced the
					// same content checksum leaves the rollback target untouched.
					// Caveat: a checksum-stable but content-changing rebuild (a
					// challenge-type change, or a cmgr release with a different
					// built-in Dockerfile — see contentChecksum) is not rotated,
					// so its displaced image is left dangling rather than
					// retained; that class falls outside the {current, previous}
					// retention guarantee.
					build.PrevChecksum = rotatedPrevChecksum(oldChecksum, build.Checksum, build.PrevChecksum)

					// Update database
					err = m.finalizeBuild(build)
					if err != nil {
						errs = append(errs, err)
						continue
					}

					// Stop and tear down existing instances. For persistent (non-on-demand)
					// instances also restart them with the new image. On-demand (dynamic)
					// instances are started per-user with injected env vars, so they are
					// only torn down here and not restarted. Non-service challenges never
					// run instances, so any found here are placeholders left by older
					// versions of cmgr and are removed entirely.
					revPortMap, err := m.getReversePortMap(build.Challenge)
					if err != nil {
						errs = append(errs, err)
						continue
					}
					instances, err := m.getBuildInstances(build.Id)
					if err != nil {
						errs = append(errs, err)
						continue
					}
					for _, iid := range instances {
						instance, err := m.lookupInstanceMetadata(iid)
						if err == nil && !cMeta.NeedsInstance() {
							if err = m.stopInstance(instance); err != nil {
								errs = append(errs, err)
							}
							continue
						}
						if err == nil {
							err = m.stopContainers(instance)
						}
						if err == nil {
							err = m.stopNetwork(instance)
						}
						if err == nil && build.InstanceCount != DYNAMIC_INSTANCES {
							err = m.startNetwork(instance, cMeta.ChallengeOptions.NetworkOptions)
						}
						if err == nil && build.InstanceCount != DYNAMIC_INSTANCES {
							err = m.startContainers(build, instance, cMeta.ChallengeOptions.Overrides, nil, revPortMap)
						}
						if err != nil {
							errs = append(errs, err)
						}
					}

					// The displaced generation (two rebuilds back) leaves
					// retention; the just-replaced one survives as the
					// rollback target. Its tags are reconstructed over the
					// current host set — a generation built with different
					// hosts leaves strays for a future sweep to reclaim.
					if pruneOldImages && displacedPruneCandidate(oldChecksum, build.Checksum, displaced) {
						displacedMeta := BuildMetadata{
							Challenge: build.Challenge,
							Seed:      build.Seed,
							Format:    build.Format,
							Checksum:  displaced,
						}
						tags := make([]string, 0, len(build.Images))
						for _, image := range build.Images {
							tags = append(tags, fmt.Sprintf("%s:%s", build.Challenge, displacedMeta.dockerId(image)))
						}
						replaced = append(replaced, replacedImages{tags: tags, meta: displacedMeta})
					}
				}

				// Pruning waits until every build of this challenge has been
				// processed: other rows can still hold the displaced checksum
				// as their current or rollback generation until their own
				// rebuild lands (or if it failed above) — contentReferenced
				// keeps the images alive in all of those cases.
				m.pruneReplacedImages(replaced)
			}
		}
	}
	return errs
}

func (m *Manager) removeChallenges(removedChallenges []*ChallengeMetadata) error {
	txn := m.db.MustBegin()
	for _, metadata := range removedChallenges {
		// This should throw an error and cause a rollback when builds exist for
		// a challenge we are removing.
		_, err := txn.Exec("DELETE FROM challenges WHERE id = ?;", metadata.Id)
		if err != nil {
			m.log.error(err)
			rbErr := txn.Rollback()
			if rbErr != nil { // If rollback fails, we're in trouble.
				m.log.error(rbErr)
				return rbErr
			}
			return err
		}
	}

	if err := txn.Commit(); err != nil { // It's undocumented what this means...
		m.log.error(err)
		return err
	}

	return nil
}

// Database representation of ContainerOptions
// List-based options are serialized as JSON strings
type dbContainerOptions struct {
	Host            string
	Init            bool
	Cpus            string
	Memory          string
	Ulimits         string
	PidsLimit       int64
	ReadonlyRootfs  bool
	DroppedCaps     string
	NoNewPrivileges bool
	DiskQuota       string
	CgroupParent    string
	CapImmutable    bool
	Seccomp         string
}

func newFromDbContainerOptions(dbOpts dbContainerOptions) (ContainerOptions, error) {
	cOpts := ContainerOptions{}

	cOpts.Init = dbOpts.Init

	cOpts.Cpus = dbOpts.Cpus

	cOpts.Memory = dbOpts.Memory

	ulimits := make([]string, 0)
	err := json.Unmarshal([]byte(dbOpts.Ulimits), &ulimits)
	if err != nil {
		return cOpts, err
	}
	cOpts.Ulimits = ulimits

	cOpts.PidsLimit = dbOpts.PidsLimit

	cOpts.ReadonlyRootfs = dbOpts.ReadonlyRootfs

	droppedCaps := make([]string, 0)
	err = json.Unmarshal([]byte(dbOpts.DroppedCaps), &droppedCaps)
	if err != nil {
		return cOpts, err
	}
	cOpts.DroppedCaps = droppedCaps

	cOpts.NoNewPrivileges = dbOpts.NoNewPrivileges

	cOpts.DiskQuota = dbOpts.DiskQuota

	cOpts.CgroupParent = dbOpts.CgroupParent
	cOpts.CapImmutable = dbOpts.CapImmutable

	cOpts.Seccomp, err = unmarshalSeccompOptions(dbOpts.Seccomp)
	if err != nil {
		return cOpts, err
	}

	return cOpts, nil
}

func (cOpts ContainerOptions) toDbContainerOptions() (dbContainerOptions, error) {
	dbOpts := dbContainerOptions{}

	dbOpts.Init = cOpts.Init

	dbOpts.Cpus = cOpts.Cpus

	dbOpts.Memory = cOpts.Memory

	ulimitsBytes, err := json.Marshal(cOpts.Ulimits)
	if err != nil {
		return dbOpts, err
	}
	ulimits := string(ulimitsBytes)
	dbOpts.Ulimits = ulimits

	dbOpts.PidsLimit = cOpts.PidsLimit

	dbOpts.ReadonlyRootfs = cOpts.ReadonlyRootfs

	droppedCapsBytes, err := json.Marshal(cOpts.DroppedCaps)
	if err != nil {
		return dbOpts, err
	}
	droppedCaps := string(droppedCapsBytes)
	dbOpts.DroppedCaps = droppedCaps

	dbOpts.NoNewPrivileges = cOpts.NoNewPrivileges

	dbOpts.DiskQuota = cOpts.DiskQuota

	dbOpts.CgroupParent = cOpts.CgroupParent
	dbOpts.CapImmutable = cOpts.CapImmutable

	dbOpts.Seccomp, err = marshalSeccompOptions(cOpts.Seccomp)
	if err != nil {
		return dbOpts, err
	}

	return dbOpts, nil
}

const (
	challengeInsertQuery string = `
	INSERT INTO challenges (
		id,
		name,
		namespace,
		challengetype,
		description,
		details,
		sourcechecksum,
		metadatachecksum,
		path,
		solvescript,
		templatable,
		maxusers,
		category,
		points
	)
	VALUES (
		:id,
		:name,
		:namespace,
		:challengetype,
		:description,
		:details,
		:sourcechecksum,
		:metadatachecksum,
		:path,
		:solvescript,
		:templatable,
		:maxusers,
		:category,
		:points
	);`

	challengeUpdateQuery string = `
	UPDATE challenges SET
	    name = :name,
		challengetype = :challengetype,
		description = :description,
		details = :details,
		sourcechecksum = :sourcechecksum,
		metadatachecksum = :metadatachecksum,
		path = :path,
		solvescript = :solvescript,
		templatable = :templatable,
		maxusers = :maxusers,
		category = :category,
		points = :points
	WHERE id = :id;`
)
