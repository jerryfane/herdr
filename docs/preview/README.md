# Preview documentation

`website/` is the committed documentation snapshot for the active preview release recorded in `distribution/preview.json`.

Do not edit it manually. Preview CI replaces it from the selected commit's `docs/next/website` tree and commits the snapshot together with `distribution/preview.json`. Validate it with:

```bash
node scripts/docs/preview.mjs check
```

## Preview manifest (schema 2)

`scripts/preview.py manifest` writes `distribution/preview.json` with `"schema_version": 2`. Compared with schema 1:

- `commit_time`, at the top level and in every new `builds[<id>]` entry, is the committer time of `commit` in unix seconds (`git show -s --format=%ct <commit>`). Servers only offer an update when the manifest commit is different and newer than their own, so an old signed manifest can't be replayed as a downgrade.
- Every asset object, at the top level and in `builds[<id>].assets`, has `sha256` (64 hex, required for every target now, not just Windows) and `size` (the release asset's size in bytes, a positive integer).

CI passes `--sha-file preview-sha256.json` and `--size-file preview-size.json`, two JSON objects keyed by target. Both are produced from the release artifacts in the "Generate notes and checksums" step. `--commit-time` defaults to the git committer time of `--commit`. The command refuses any target that is missing a sha256 or a size. Older `builds` entries written under schema 1 are kept as they are, without `commit_time` or `size`. Update verification only reads the top-level build.

## Signing

`distribution/preview.json.minisig` is a minisign signature, prehashed (`ED`), over the exact bytes of `distribution/preview.json`. Its trusted comment is `herdr-preview <build_id> <commit>`, with the full 40-hex commit. The private key is not on GitHub, so CI never signs. When the preview workflow replaces the manifest, it removes the old `.minisig` in the same commit, so a stale signature is never paired with a new manifest. Until the new `.minisig` is committed, servers report "update not ready yet" and offer nothing.

After CI publishes a preview, an operator on a fleet box signs it through the role's keyring relay:

```bash
git pull
python3 scripts/preview.py sign \
  --keyring-url "http://127.0.0.1:7700/<role>/_keyring/minisign/herdr-release"
git add distribution/preview.json.minisig
git commit -m "chore(preview): sign <build_id>"
git push
```

The commit subject follows Conventional Commits, because CI lints every subject pushed to master.

`sign` takes `--manifest` (default `distribution/preview.json`), `--keyring-url` (the full relay route) and `--timeout` (seconds, default 120). It POSTs `{"blake2b512_hex": "<BLAKE2b-512 of the manifest bytes>", "trusted_comment": "herdr-preview <build_id> <commit>"}` to the relay. The relay answers `{"minisig": "<.minisig file text>"}`. Before writing, `sign` checks the returned text: four lines (untrusted comment, signature, `trusted comment: …`, global signature), a 74-byte `ED` signature, a 64-byte global signature, and the exact trusted comment. If anything is wrong, it exits non-zero and writes nothing. Otherwise it writes `<manifest>.minisig` atomically.

Owner fallback without the relay, on the machine that holds the key:

```bash
minisign -S -H -m distribution/preview.json -t "herdr-preview <build_id> <commit>"
```

`-H` (prehashed) is already the default in current minisign; pass it anyway so the `ED` algorithm is explicit. Read `build_id` and `commit` from `distribution/preview.json`.
