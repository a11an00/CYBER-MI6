# Docs in 2 minutes

**The rule:** docs ship in the same pull request (PR) as the code. No "I'll document it later".

## 1. Every file starts with a plain-words header

No jargon. Write it so a teammate who has never seen the file gets it in 30 seconds.
Keep it short: it should still be true after the file changes a little.

```python
"""
WHAT: What this file is for, in one or two sentences.
HOW:  The main flow in plain words (a few sentences, not line by line).
LINKS: Other files it depends on or that depend on it.
WATCH OUT: Anything surprising, fragile, or non-obvious. Delete if none.
"""
```

Same four parts in any language (`/** ... */` in JavaScript, `#` lines in shell, `--` lines in SQL).

**Functions:** add a docstring with what it does, inputs, output, and errors it can raise.
If you change a function or a file, update its docstring/header in the same commit.

## 2. Pages in `docs/` (one job per page, never mixed)

| Page | Job | Reader is... |
|---|---|---|
| `tutorials/getting-started.md` | Guided first run that works every time | learning |
| `how-to/<task>.md` | Steps to do one specific thing | doing |
| `reference/config-and-api.md` | Exact facts: env vars, endpoints, commands | looking up |
| `explanation/architecture.md` | How the parts fit together and why | understanding |

Not sure where something goes? Learning, doing, looking up, or understanding: pick one.
If a page needs two, split it and link them. Add new how-to pages only when someone needs one.

## 3. In every PR

- Behavior, config, endpoint, or structure changed? Update the affected page(s). Search `docs/` for the names you touched.
- Add a line to `CHANGELOG.md` under `Unreleased` if users or teammates will notice.
- Nothing to document? Tick "No docs impact" in the PR and say why in one sentence. The reviewer checks it.
- Run any command or example you wrote before committing.
- Never put secrets, keys, or real personal data in docs. Use placeholders like `YOUR_API_KEY`.

**Where does "what changed and why" go?** The PR description and `CHANGELOG.md`.
Doc pages describe how things work *now*, not their history.

## 4. Reviewers

Check: docs match the change, the "No docs impact" reason is true, each page has one job,
header/docstrings match the code. Missing docs means changes requested.
Hotfix exception: merge now, docs PR within 2 working days.

## PR template

Save as `.github/pull_request_template.md`:

```markdown
## What changed and why

## Docs
- [ ] Updated: (list pages)
- [ ] Headers/docstrings updated
- [ ] CHANGELOG entry added
- [ ] No docs impact. Reason:
```
