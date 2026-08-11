# Security policy

Report vulnerabilities privately through GitHub's security advisory feature.
Do not open a public issue containing a secret, proprietary corpus or local
installation path.

The beta trusts adapter and module code running in-process. Hostile adapter
sandboxing is not implemented. Game build and installation are outside the
package. Filesystem publication validates containment, links/reparse points,
preimages, leases and receipt bindings, but callers remain responsible for
using a dedicated workspace and exact dependency pins.

Only the latest beta receives security fixes before a stable release.
