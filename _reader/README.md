# Atlas Reader builder

Builds `../read/`, the password-protected reader for the Sutskever reading list.
Jekyll does not publish this folder because its name starts with `_`.

Each explainer is converted with pandoc, its math is typeset with KaTeX, and every
page and PDF is encrypted with AES-GCM under a key derived from the password
(PBKDF2-SHA256, 600,000 rounds). The repository only holds encrypted files.

## Build

    atlas-reader-build

The first build asks for a new password twice. Later builds ask once and must use
the same password, or every file is encrypted again. The password can also come
from `$ATLAS_READER_PASSWORD` or from `~/.config/atlas-reader/password`.

Unchanged files keep their name, so a rebuild after editing one explainer only
changes that file and the manifest.

## Files

- `build.mjs`: the builder. Source folder: `~/Documents/AI Research/Ilya Sutskever Reading List`.
- `web/`: the reader app, copied into `../read/` on every build.
