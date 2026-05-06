# Releasing PeerNet

Checklist for cutting a Hex release. The codebase itself is ready;
this is the human/admin loop.

## Pre-flight

- [ ] `mix test` is green (3 consecutive runs — there are timing-
      sensitive Liveness/Reconnect tests, run a few times to catch
      timing flakes if any).
- [ ] `mix credo --strict` reports zero issues.
- [ ] `mix compile --warnings-as-errors` is clean.
- [ ] `mix docs` builds without warnings; `doc/index.html` looks
      sensible.
- [ ] `CHANGELOG.md` is up to date — every meaningful change since
      the previous tag has an entry.
- [ ] `mix.exs` `@version` is bumped per semver.
- [ ] `README.md` Status section reflects what actually works.
- [ ] `git status` is clean (no untracked files in the package
      tree).

## Hex tooling note

Current `hex 2.4.1` calls `:re.import/1`, which was removed in
OTP 28. Until Hex publishes a fix, run `mix hex.publish` from an
OTP 27 BEAM (or whichever version Hex's CI is currently on) — the
package metadata in `mix.exs` is correct; the issue is purely with
the build/upload tooling.

## Cutting the release

```bash
# Verify the package contents (what'll actually go into the tarball):
mix hex.build --dry-run    # under OTP 27

# Verify auth (one-time setup):
mix hex.user whoami

# Cut the release:
mix hex.publish

# Tag in git after Hex acknowledges:
git tag v0.X.Y
git push origin v0.X.Y
```

## Post-release

- [ ] Verify package on https://hex.pm/packages/peer_net
- [ ] Verify docs render at https://hexdocs.pm/peer_net
- [ ] Update `mix.exs` `@version` to next dev version (e.g.
      `0.X.Y-dev`) so further commits don't accidentally re-publish
      the same number.
- [ ] Open a GitHub release with the relevant `CHANGELOG.md`
      excerpt as the body.

## What goes in the tarball

`mix.exs` `package: [files: ...]` controls this explicitly:

```elixir
files: ~w(lib LICENSE mix.exs README.md CHANGELOG.md PLAN.md guides .formatter.exs)
```

That includes:
- `lib/` — all source
- `LICENSE`
- `mix.exs`
- `README.md`, `CHANGELOG.md`, `PLAN.md`
- `guides/` — protocol.md and cookbook.md
- `.formatter.exs` — so downstream `mix format` honors our style

Excluded by default: `test/`, `doc/`, `_build/`, `deps/`, `tmp/`,
`.git/`, the `RELEASING.md` you're reading. Test code isn't
shipped in the package; users who want to run our tests clone the
repo.

## Versioning policy

Pre-1.0:

- **0.x.0** — meaningful new features or breaking changes (no
  compatibility promises while in 0.x).
- **0.x.y** — bug fixes, doc improvements, no API changes.

Post-1.0: standard semver — major for breaks, minor for additions,
patch for fixes.
