# Public evidence preservation

This guide describes how to document public material during an authorized investigation. It does not recommend downloading, redistributing or publishing personal data, credentials, illegal material or protected content without a lawful and necessary basis for retention.

## What to preserve

Record the original URL, the capture date and time in UTC, the capture type, the filename, the SHA-256 hash and any transformations applied. When possible, also record an Internet Archive capture or a Memento reference. A screenshot alone does not replace the URL, timestamp and source context.

For web pages, HTML or PDF may be preserved together with a visual capture. For documents and attachments, retain the original only when it is lawful and necessary; otherwise record the minimum metadata needed and avoid copying personal data. For videos, record the URL, post identifier, capture time and frames used for analysis, without redistributing the video unless necessary.

## Minimum workflow

1. Define the objective, scope and lawful basis for the investigation.
2. Record the exact URL and UTC time before modifying or downloading anything.
3. Capture the material with a reproducible archiving or export method.
4. Calculate SHA-256 for every retained file.
5. Record the archive reference, method and access limitations.
6. Separate observed facts, inferences and conclusions.
7. Redact or remove personal data that is not necessary for the objective.
8. Store the manifest with the files, using access controls and a defined retention period.

## Synthetic manifest

The following example is deliberately fictional and does not represent a real investigation:

```yaml
case_id: example-0001
source_url: https://example.org/
captured_at: 2026-10-20T22:00:00Z
capture_type: html
original_filename: public-report.html
sha256: 0000000000000000000000000000000000000000000000000000000000000000
archive_url: null
transformations: []
sensitivity: public-example
retention: review-after-90-days
notes: Synthetic example; contains no real target data.
```

## Interpretation limits

A preserved file shows what was available at a particular time. It does not by itself prove the author's identity, the truth of the content or the absence of earlier edits. C2PA credentials provide provenance signals and should be interpreted together with independent verification, chronology, metadata and other sources.

## References

- [Internet Archive Wayback Machine APIs](https://archive.org/help/wayback_api.php)
- [C2PA Specifications 2.4](https://spec.c2pa.org/specifications/specifications/2.4/index.html)
