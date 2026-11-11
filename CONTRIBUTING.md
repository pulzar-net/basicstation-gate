# Contributing

Issues and pull requests are welcome. For a security problem, see
[SECURITY.md](SECURITY.md) instead of opening an issue.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

Python 3.10 or later. The unit tests need nothing else.

## The real station

`tests/test_station.py` is skipped until the Basics Station is built:

```bash
scripts/build-station.sh
```

It clones `lorabasics/basicstation` at v2.0.6 into `build/station/` and builds
the `testsim` variant. On Linux it needs `gcc`, `make` and `git`. On macOS it
needs Xcode's command line tools and `brew install argp-standalone`; the
shims it applies are in `scripts/station-macos-compat.h`.

`scripts/compose-e2e.sh` also needs Docker. It builds the image, runs
`examples/compose.yaml` with ChirpStack Gateway Bridge, connects the station
and tears everything down.

CI runs the unit tests, the station tests and the compose test on every pull
request. A change to the protocol should come with a test that a real station
would fail without it.

## Changes

- Keep `basicstation_gate.cups` free of dependencies.
- Anything that decides whether a gateway gets in fails closed: a backend
  error, a timeout or an unexpected answer is a no.
- Keys stay in the signer. The public process must not be able to read them
  or get arbitrary bytes signed.
- Test certificates and keys are generated in the tests. Do not commit any.
- Note user-visible changes in `CHANGELOG.md`.

By contributing you agree that your contribution is licensed under
Apache-2.0, the license of this project.
