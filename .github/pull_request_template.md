**What changes and why**

**Checks run** (see CONTRIBUTING.md; say plainly which you could not run)

- [ ] `python tests/vectors.py` and `node tests/vectors.mjs`
- [ ] `python tools/release.py check` (after a client change, run `python tools/release.py build` first and commit the manifest)
- [ ] `python tools/prepublish.py --self-test` and `python tools/prepublish.py`
- [ ] `tests/e2e.mjs`, for a change to the server, the caller or the client
- [ ] `CHANGELOG.md` has a line under Unreleased
