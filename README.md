# FACT raw campaign data

Raw per-run data for the experimental campaigns of FACT, the artifact of the
NOMS 2027 paper. Code, summarized CSVs and figures are in
[hhermany/fact](https://github.com/hhermany/fact) (tag `noms2027`).
This is the `raw-data` branch of that repository; fetch it alone with

```sh
git clone --branch raw-data --single-branch https://github.com/hhermany/fact.git fact-raw-data
```

Each file in `archives/` is one campaign directory
(`campaigns/<campaign_id>/` in the FACT repository) packed as
`<campaign_id>.tar.gz`, with its per-run logs, event traces and manifests.

## Verifying

`SHA256SUMS` lists the SHA-256 of every complete archive. Archives larger than
90 MiB are stored in parts (`<campaign_id>.tar.gz.partNN`, checksums in
`PARTS.sha256`) to stay under GitHub's file size limit. Rejoin them first:

```sh
cd archives
for f in $(ls *.part00 2>/dev/null); do b=${f%.part00}; cat "$b".part?? > "$b"; done
cd .. && (cd archives && sha256sum -c ../SHA256SUMS)
```

Inside each campaign, `checksums.sha256` (when present) holds the SHA-256 of
every raw file, and the same file is committed in the FACT repository.

## Using

Extract an archive into the `campaigns/` directory of a FACT checkout and
follow "Regenerating the summarized CSVs" in the FACT README:

```sh
tar -xzf archives/<campaign_id>.tar.gz -C /path/to/fact/campaigns
```

Model names that appear in the logs (for example in the agent-driven
campaigns) are the experiment subjects, not authors of the data.
