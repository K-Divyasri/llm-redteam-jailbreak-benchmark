# Pre-publish checklist

- [ ] `python -m pytest` - all 28 tests pass
- [ ] `python -m redteam full --out REPORT.md --generated-at "<real UTC timestamp>"` -
      re-run and re-commit `REPORT.md` with a real timestamp before publishing
      (the version in the repo right now has a placeholder/build-time date -
      replace it with the date you actually publish)
- [ ] `streamlit run app.py` locally - click "Run full scan", confirm all 4 tabs
      and the download button work
- [ ] `git status` shows nothing unexpected - especially no `.env` file
- [ ] `vendor/data/company.db` is present and committed (the
      agent's database tool needs it; CI regenerates it too, but a fresh clone
      should work without running anything first)
- [ ] Root `README.md` states the real, current headline numbers (raw 26/29,
      guarded 16/29, hardened 0/29 + 3 false positives, agent 0/4) - don't let
      this drift from `REPORT.md` if you ever add or change an attack
- [ ] GitHub Actions is green on the `main` branch before you link the repo
      anywhere public
- [ ] If you extended `app.py` to call `redteam/real_llm.py`: confirm no real
      API key is hardcoded anywhere, and that the demo still runs with the key
      unset (the offline path must always be the default)
