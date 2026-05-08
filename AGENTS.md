# AGENTS.md

## Project purpose

VyOS fork of the upstream `pam_radius_auth` PAM module — turns any host into a RADIUS client for authentication, password change, and (Linux-only) session accounting. Ships as the Debian source package `vyos-libpam-radius-auth`, plus a `vyos-radius-shell` companion package (shell front-end for RADIUS users).

## Tech stack

- C, GNU autotools (`configure.ac`, `Makefile`, `acinclude.m4`, `m4/`).
- Debian packaging in `debian/` (debhelper >= 12, `libpam0g-dev`, `libaudit-dev`, `libcap-dev`).
- License: GPL-2.0 (per `LICENSE`).

## Build / test / run

```sh
autoreconf -i           # generate./configure from configure.ac
./configure
make
dpkg-buildpackage -us -uc # produces vyos-libpam-radius-auth + vyos-radius-shell.debs
```

No in-tree test runner. Configuration lives at `pam_radius_auth.conf`; man pages at `pam_radius_auth.5`/`.8`, `radius_shell.8`.

## Repository layout

- `src/` — module source.
- `pam_radius_auth.conf`, `pam_radius_auth.5`/`.8` — config + manpages.
- `pamsymbols.ver` — symbol export map.
- `debian/`, `pam_radius_auth.spec` — Debian and RPM packaging.
- `Jenkinsfile` — legacy upstream CI (not used by VyOS pipeline).

## Cross-repo context

Authentication building block consumed by the VyOS image. Built by the internal build-packages workflow and pulled into the ISO via `vyos/vyos-build`. Sibling auth repos: `libpam-tacplus`, `libnss-tacplus`, `libnss-mapuser`, `libtacplus-map`. Used by `vyos-1x` conf-mode scripts that wire `pam_radius` into `/etc/pam.d`.

## Conventions

- Default branch `current`; LTS branches `sagitta`/`circinus` when used.
- Commit / PR title format: `component: T12345: description` (Phorge task ID at https://vyos.dev).
- Treat as upstream-vendored: keep diffs against the original `pam_radius` minimal; large feature work goes in VyOS-specific glue rather than this fork.

## Notes for future contributors

- Renamed source/binary packages (`vyos-libpam-radius-auth`, `vyos-radius-shell`) on purpose — do not revert to upstream `libpam-radius-auth` package names without a coordinated change in `vyos-build-packages` and `vyos-1x` PAM templates.
- The `Jenkinsfile` is upstream cruft; VyOS CI runs through GitHub Actions reusables in `vyos/.github`.
