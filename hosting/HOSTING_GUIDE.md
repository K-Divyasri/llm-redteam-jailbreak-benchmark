# Publishing the LLM Red-Team & Jailbreak Benchmark

This project is two things at once: a tested Python package (`redteam`) you run
from the command line to produce `REPORT.md`, and a small Streamlit app that lets
someone browse the same findings in a browser. "Hosting" here means two jobs:

1. Get the **source** onto GitHub with CI that re-runs the 28 tests on every
   push - this is the part that matters most for an interview, because it's
   evidence a stranger can click and verify, not a claim in a README.
2. Get the **demo app** running somewhere public so someone can click "Run full
   scan" and watch the findings appear without installing anything.

Do them in that order. Everything below assumes you're working from
`ai/36-llm-redteam-jailbreak-benchmark/` - the folder containing `knowledge/`,
`notebooks/`, `labs/`, `build_from_scratch/`, and this `hosting/` folder. That
whole project folder is what becomes the GitHub repo. `build_from_scratch/` is
the polished deliverable subfolder inside it - both `app.py` and
`requirements.txt` live there, not at the repo root.

---

## Step 1 - Get it on GitHub

If you've never used Git before, "Step 0" of
`ai/01-data-detective/hosting/HOSTING_GUIDE.md` walks through installing Git,
making a GitHub account, and telling Git who you are. From here on this guide
assumes `git --version` already works.

### 1a. Check what must never be committed

Open `ai/36-llm-redteam-jailbreak-benchmark/build_from_scratch/.gitignore` and
confirm it has at least:

```
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
.env
```

The line that matters most is `.env`. If you ever ran the optional `--real`
system-prompt-leak probe (`redteam/real_llm.py`), you put a real API key in
`build_from_scratch/.env`. That file must never be committed - the repo ships
`build_from_scratch/.env.example` instead (variable names, no values), and
that one IS meant to be committed. If a key ever does end up on GitHub, treat it
as burned - revoke and re-issue it with the provider before doing anything else.

Note what's committed on purpose here, unlike some other projects in this
roadmap: `build_from_scratch/vendor/data/company.db` IS checked in. It's a tiny
(fifteen-row) deterministic SQLite file the vendored agent's database tool
reads - committing it means a fresh clone works immediately with no setup step,
and CI regenerates it anyway as a safety net (see Step 2).

### 1b. Init, commit, push

From `ai/36-llm-redteam-jailbreak-benchmark/` (the project root, one level above
`build_from_scratch/`):

```powershell
git init
git add .
git commit -m "LLM red-team and jailbreak benchmark: attacks, scoring, report"
git status
```

You want `nothing to commit, working tree clean`, and you must **not** see
`.env` listed. Then create an empty, public repo on github.com (name it
something like `llm-redteam-jailbreak-benchmark`, and don't tick "Add a
README" or "Add .gitignore" - you already have both):

```powershell
git branch -M main
git remote add origin https://github.com/YOURNAME/llm-redteam-jailbreak-benchmark.git
git push -u origin main
```

Refresh the repo page - you should see `knowledge/`, `notebooks/`, `labs/`,
`build_from_scratch/`, `hosting/`, and this project's root `README.md`.

---

## Step 2 - Add CI

The workflow at `hosting/github_actions/ci.yml` runs on every push and pull
request: install dependencies, regenerate the agent's SQLite fixture (a
deterministic no-op if it's already committed correctly), run the 28 pytest
tests, and print a fresh scan summary into the log.

This is worth noticing what it does NOT do compared to a defensive project's
CI: it isn't a ship gate that fails the build if a vulnerability is found -
finding vulnerabilities is this project's entire JOB, not a regression. What
the tests actually pin down (see `tests/test_report.py`) is that the scan stays
*reproducible* - the same 26/16/0/0 vulnerability counts every run, because
nothing in the corpus or either target has any randomness in it. If a future
change to the vendored `safeguard` or `tool_agent` code shifts those numbers,
CI goes red - the correct response is to re-read the report and understand
*why* the numbers moved, not to edit the assertion until it's green again.

Install it:

```powershell
mkdir .github\workflows
copy hosting\github_actions\ci.yml .github\workflows\ci.yml
git add .github\workflows\ci.yml
git commit -m "Add CI: dependencies, fixture, tests, scan summary"
git push
```

Open the **Actions** tab on GitHub and watch it go green.

---

## Step 3 - Deploy the Streamlit demo to Hugging Face Spaces

A Space is its own small Git repo, separate from the GitHub one above. Unlike
some simpler projects in this roadmap, this app needs THREE things copied in,
not one - `app.py` imports `redteam`, which in turn imports the two vendored
packages under `vendor/`:

- `app.py` - copy from `build_from_scratch/app.py`.
- `requirements.txt` - use `hosting/space/requirements.txt` (just `streamlit` -
  the demo never calls the optional real-LLM path, so it doesn't need `litellm`).
- `redteam/` - the package itself, copied wholesale from `build_from_scratch/redteam/`.
- `vendor/` - copied wholesale from `build_from_scratch/vendor/`, INCLUDING
  `vendor/data/company.db` (the agent's tool_agent database tool needs it to exist).
- `README.md` with YAML front-matter - use `hosting/space/README.md` as-is.

```powershell
git clone https://huggingface.co/spaces/YOURNAME/llm-redteam-jailbreak-benchmark
cd llm-redteam-jailbreak-benchmark

copy ..\36-llm-redteam-jailbreak-benchmark\build_from_scratch\app.py .
copy ..\36-llm-redteam-jailbreak-benchmark\hosting\space\requirements.txt .
copy ..\36-llm-redteam-jailbreak-benchmark\hosting\space\README.md .
xcopy ..\36-llm-redteam-jailbreak-benchmark\build_from_scratch\redteam redteam\ /E /I /EXCLUDE:nul
xcopy ..\36-llm-redteam-jailbreak-benchmark\build_from_scratch\vendor vendor\ /E /I /EXCLUDE:nul

git add .
git commit -m "Deploy red-team benchmark demo"
git push
```

(Adjust the `..\36-llm-redteam-jailbreak-benchmark\` prefix to wherever your
project folder actually sits relative to the cloned Space. If any
`__pycache__/` folders got copied along, delete them - compiled bytecode,
not needed.)

Hugging Face builds and starts the app automatically. Open the Space's URL,
click "Run full scan", and you should see the same 26/16/0/0 numbers this
project's own `REPORT.md` shows.

### The optional API key

The public demo works with **no key at all** - the app never calls
`redteam/real_llm.py`. If you want to extend the app yourself to expose that
probe publicly, add a Space **secret** (Settings -> Variables and secrets ->
New secret), name it `GEMINI_API_KEY`, and `real_llm.has_api_key()` will pick
it up the same way it reads a local `.env` - Spaces injects secrets as
environment variables, no code change needed. Leave it unset for the demo as
shipped; every finding in this project is already fully reproducible offline.

---

## Step 4 - Alternative: Streamlit Community Cloud

If you'd rather point at the GitHub repo from Step 1 instead of maintaining a
second Space repo:

1. Go to https://share.streamlit.io, sign in with GitHub, authorize access to
   your `llm-redteam-jailbreak-benchmark` repo.
2. Click **New app**, pick that repo and the `main` branch.
3. Set **Main file path** to `build_from_scratch/app.py` - the one field that
   matters, since `app.py` isn't at the repo root.
4. Deploy. Community Cloud looks for a `requirements.txt` next to the app file
   it's running, so it picks up `build_from_scratch/requirements.txt`
   automatically - this pulls in `litellm` too (harmless, just unused unless
   you wire the optional real-LLM probe into the UI yourself).

Community Cloud has the advantage here of needing no separate copy step at
all - it reads straight from the one repo, `vendor/data/company.db` included,
because the whole `build_from_scratch/` tree is already exactly what the app
needs. Pick either host; don't feel obliged to set up both.
