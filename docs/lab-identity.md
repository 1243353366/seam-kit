# Two questions that look like one

Authentication: is this the person they claim to be. Authorization: may this person do this.
Every serious access-control failure I can think of lives in the gap, and the gap is invisible in
a log that records successful logins.

`lab/identity.py` models the distinction with four rules, each of which has a test:

- A signature over subject, role, validity window, nonce and device. Changing the role breaks it.
- Expiry is checked before permission, so an expired credential never reaches a policy decision.
- A nonce can be spent once. The same credential presented twice is a replay, not a retry.
- A credential bound to `reader-1` presented from `reader-9` is refused even if it verifies.

The test that matters is the one where a restorer authenticates successfully and is then refused
`vault:open`. Both answers are recorded, because a refusal is evidence.

`audit_gaps()` exists for the other half of the problem: actions nobody attempted look identical
to actions whose records were removed, so a gap is reported as a gap rather than assumed benign.

## Temporal signals

`lab/temporal.py` measures the three things a single frame cannot show, and all three are ratios
against the sequence's own behaviour rather than absolute thresholds:

- **flicker**: peak-to-peak swing in region brightness and high-frequency energy. Measured as a
  swing, not as frame-to-frame differences, because an alternating pulse changes on every step and
  a difference ratio calls that stable. That bug existed here for one commit.
- **drift**: the face region's 16x16 grayscale grid compared against the sequence median. Colour
  histograms were the first attempt and they said "skin is skin" for every face.
- **cut**: largest frame-to-frame luma change over the median change.

`load_video()` decodes through ffmpeg at a fixed size, and the container test writes H.264 and
reads it back, because a codec can invent or hide grain and an untested container assumption is
how a detector ends up measuring the encoder.

None of these establishes synthesis. A dropped frame, a strobe light, a hard cut in the edit and
a re-encode all move them, and the point of the ratio form is to make that obvious.

## Still unbuilt

Multi-camera reconstruction, drone telemetry consistency, audio-visual sync, and the perception
experiment. Each needs a different data path (projection geometry, IMU traces, waveform alignment,
human subjects) and none of them is honestly testable in an afternoon. They are listed here rather
than implied by a folder name.
