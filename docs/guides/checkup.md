# Shareable checkup card

`checkup` writes a self-contained HTML card with a 1200×630 crop and prints a
Markdown sticker line. It shows counts, date, coverage-qualified grade or
**Preview**, and “reach and hygiene, not a safety certificate.” Names are absent
unless `--names` is supplied; even then, paths, hostnames, credential key names
and tool text stay out of the card. Nothing is uploaded. The default destination
is `checkup.html`. `checkup --connect --server ID` uses the same explicit
connection boundary as `check` and adds the card's metadata checks.

Legacy `scan --card checkup.html` writes the same card without changing its
connection behavior or enabling extra checks. Optional `--previous report.json`
compares an explicitly selected earlier local report when inventory and coverage
match; there is no automatic history or streak tracking. The printed sticker
contains counts and the caveat, with no hosted badge or link.

The card is reach and hygiene, not a safety certificate. Review it before
sharing, like any report.
