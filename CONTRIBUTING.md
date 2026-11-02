# Contributing to auth-ai (Python)

> Welcome — this document covers contributor onboarding, versioning policy,
> releases and the Git workflow. **All technical standards** (typing,
> architecture, testing, error handling, security) live in
> [AGENTS.md](AGENTS.md) and are the canonical reference. Read both documents
> before opening a PR.

---

## 1. Development environment

### Prerequisites

- Python 3.12+ (the CI also runs 3.13 and 3.14)
- pip 25.1+ (for `--group`, PEP 735)
- Docker (optional: to build the example app and the documentation image)

### First-time setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[starlette]" --group dev
pytest              # unit suite, no network
```

The unit tests run against a scripted mock identity provider
(`tests/support/mock_idp.py`): no auth-service instance is needed.

### Daily commands

For the full command table see [AGENTS.md → Build & Test Commands](AGENTS.md#build--test-commands).

| Command          | When to run                 |
| ---------------- | --------------------------- |
| `pytest -x`      | While developing            |
| `mypy`           | Before committing           |
| `pytest --cov`   | Before opening a PR         |
| `ruff format .`  | To fix formatting           |
| `ruff check .`   | Before committing           |

### End-to-end check

`examples/minimal` is a deployable application whose **Self-test** button exercises
every brick against a real auth-service. Run it when a change touches sign-in,
tokens, the wallet or the gateway (see its README).

### Documentation

The documentation site lives in `docs-site/` (Docus). Build it in Docker:

```bash
docker build -t auth-ai-python-docs ./docs-site
```

---

## 2. Versioning and breaking changes

This project follows **Semantic Versioning** (`MAJOR.MINOR.PATCH`, written as a
PEP 440 version). While the major version is `0`, a breaking change bumps `MINOR`.

| Change type                      | Version bump | Required action        |
| -------------------------------- | ------------ | ---------------------- |
| Bug fix, no API change           | `PATCH`      | Changelog entry        |
| New feature, backward-compatible | `MINOR`      | Changelog entry + docs |
| Breaking change                  | `MAJOR`      | See below              |

### Breaking changes

A breaking change is anything that alters the public contract: a changed signature or
default, a removed export, a changed error code or response shape, a raised minimum
Python or dependency version.

**The rule: no backward-compatibility shims.** Bump the version, document the change
and a migration note in `CHANGELOG.md` and the docs, and remove the old behaviour.

The wire contract (BFF routes, cookie formats, error codes) is shared with the
TypeScript SDK `@circle-rd/auth-ai`: change it in both, or not at all.

---

## 3. Releases

| Channel   | Trigger                                                 | PyPI version          |
| --------- | ------------------------------------------------------- | --------------------- |
| nightly   | Manual run of the _Nightly_ workflow (`develop`/`main`) | `X.Y.Z.devYYYYMMDDHHMM` (pre-release, `pip install --pre auth-ai`) |
| stable    | A GitHub release `vX.Y.Z` created from `main`           | `X.Y.Z`               |

1. Merge `develop` into `main` through a pull request.
2. Set `version` in `pyproject.toml`, move the `[Unreleased]` entries of
   `CHANGELOG.md` under the new version, commit on `main`.
3. Create the GitHub release (and its tag `vX.Y.Z`) from `main`: this is the only
   trigger. The _Release_ workflow runs the quality gates, checks that the tag
   matches `pyproject.toml` and publishes. It never creates a release or a tag itself.
   A pre-release version (`X.Y.ZrcN`) needs a release marked _pre-release_.
4. Merge `main` back into `develop`.

If a release run fails, fix the cause, then delete the release **and** its tag and
create them again: re-running a job of a deleted tag fails at checkout. PyPI never
accepts the same version twice: bump it if a version was already uploaded.

A nightly is published as `X.Y.Z.devYYYYMMDDHHMM` without any commit (`X.Y.Z` is the
next patch when `pyproject.toml` holds an already published version). Nightlies stay
on PyPI: Trusted Publishing covers uploads only, so removing or yanking one is a
manual action on pypi.org.

Both workflows publish through PyPI Trusted Publishing (OIDC): no PyPI token is stored.
Each one must be registered as a trusted publisher of the `auth-ai` project on pypi.org
(owner `circle-rd`, repository `auth-ai-python`, workflow `release.yml` or `nightly.yml`,
environment `pypi`). Before the first upload, register them as _pending publishers_.

---

## 4. Git workflow

### Branch naming

| Type          | Pattern                        | Example                    |
| ------------- | ------------------------------ | -------------------------- |
| Feature       | `feat/<short-description>`     | `feat/django-adapter`      |
| Bug fix       | `fix/<short-description>`      | `fix/refresh-lock`         |
| Refactor      | `refactor/<short-description>` | `refactor/session-store`   |
| Chore / infra | `chore/<short-description>`    | `chore/update-ruff`        |
| Breaking      | `breaking/<short-description>` | `breaking/handler-options` |

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

[optional body]

[optional footer: BREAKING CHANGE, Closes #issue]
```

Types: `feat`, `fix`, `refactor`, `test`, `chore`, `docs`, `perf`, `build`, `ci`.

### Pull request checklist

- [ ] `ruff format --check .` and `ruff check .` pass
- [ ] `mypy` passes with zero errors
- [ ] `pytest --cov` passes (coverage threshold met)
- [ ] `python -m build` passes
- [ ] `pip-audit` reports nothing
- [ ] New behaviour has tests; a security check has a test that fails without it
- [ ] No `Any`, no dead code, no secret or token in a message, log or test output
- [ ] Docs (`docs-site/`), README quick start and `CHANGELOG.md` updated for user-visible changes
- [ ] Breaking changes bump the version and carry a migration note

For the rationale behind each gate and the standards new code must meet, see
[AGENTS.md](AGENTS.md). Security vulnerabilities must **not** be reported in a public
issue: see [SECURITY.md](SECURITY.md).
