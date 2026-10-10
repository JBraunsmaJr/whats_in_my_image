# Branch protection

`main` and the release tags are protected by the GitHub rulesets in
[`.github/rulesets/`](https://github.com/willj4945/whats_in_my_image/tree/main/.github/rulesets). To apply them, open
**Settings → Rules → Rulesets → New ruleset → Import a ruleset** and import each file:

| File                   | Effect                                                                                                                                                                      |
|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `main-protection.json` | Changes reach `main` only by pull request, all CI and Security checks must pass on an up-to-date branch, and `main` can't be force-pushed or deleted. Nobody can bypass it. |
| `main-review.json`     | Pull requests need one approving review. Repository admins may skip this when merging their own pull request, so a single maintainer isn't locked out.                      |
| `release-tags.json`    | Published `v*` tags can't be moved or deleted, so a signed release always points at the same commit.                                                                        |
