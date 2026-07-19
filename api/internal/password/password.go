// Package password hashes and verifies panel-user passwords with Argon2id.
package password

import "github.com/alexedwards/argon2id"

// params are tuned down from the library's 64 MiB default per
// compass_artifact.md's Caveats: the target host is 1 vCPU / 1 GB RAM,
// shared with Postgres, Xray, Hysteria2, and Caddy, so 64 MiB/thread risks
// OOM under concurrent logins. Memory 32 MiB, Iterations 3, Parallelism 1
// sit at the low end of the doc's recommended 32-46 MiB / 3-4 / 1 range.
var params = &argon2id.Params{
	Memory:      32 * 1024,
	Iterations:  3,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Hash returns an Argon2id PHC-format hash string, safe to store directly
// in the users.password_hash column.
func Hash(password string) (string, error) {
	return argon2id.CreateHash(password, params)
}

// Verify reports whether password matches hash. A false, nil result means
// the credentials simply didn't match; a non-nil error means hash was
// malformed or otherwise couldn't be checked.
func Verify(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
