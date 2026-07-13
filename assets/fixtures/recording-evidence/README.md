# Recording-evidence fixtures

These fixtures are sanitized protocol examples only.  They use the generic
identity `example-project`, the stable test ref `v0.0.0-test`, and the generic
oracle/direct-impact markers required by the recording gate.  They contain no
real target name, endpoint, payload, finding text, attachment path, or operator
path.

`manifest.template.json` is a shape example rather than a claim of a completed
recording.  The plugin self-test creates a tiny three-frame animated media file
locally with Pillow, captures matching temporary checkpoint images outside the
bundle, and runs the public validator against that media.  The test therefore
checks encoded media bytes and generated screenshots rather than trusting a
boolean or a sidecar result.

Each stage's `recording_time_observations` is a recorder-supplied consistency
claim, not independent proof of what the encoded video visibly contains. Full
recording-time validation requires recorder-owned live checkpoints and
source/window checks; later revalidation without those checkpoints reports only
artifact consistency.

The negative cases in the self-test mutate one gate at a time: identity/window
drift, timestamp ordering, source-frame mismatch, missing or duplicate
screenshots, missing registration, hash tampering, missing direct-impact marker,
non-zero replay, and incomplete archives.
