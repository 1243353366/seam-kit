# The lab

The point of this directory is a negative result stated up front: **no single signal identifies a
manipulated frame.** Three of the four measurements collapse to a coin flip once both corpora go
through the same surveillance processing, and the fourth is largely detecting the blur that the
generator applied, not the manipulation.

## Method

1. `lab/synth.py` builds a controlled portrait: textured background, skin oval, eyes, mouth, and
   sensor noise. `manipulate()` replaces the face with a different, Gaussian-blurred donor and
   feathers the boundary by one pixel.
2. `lab/degrade.py` pushes both corpora through identical levels: `clean`, `q75`, `q50`, and
   `cctv` (downscale by 3, blur 1.0, JPEG q50).
3. `lab/signals.py` measures four things and declares which way each one points, because a
   smoother fake lowers the residual ratio and a report that ignores direction scores a perfect
   separator as zero.
4. `lab/experiment.py` computes ROC AUC and the best Youden operating point per level, and runs a
   200-permutation label shuffle as a null control.

## Results

| signal | clean | q75 | q50 | cctv |
| --- | --- | --- | --- | --- |
| noise_ratio | 1.00 | 1.00 | 1.00 | 1.00 |
| seam_edge | 0.00 | 0.00 | 0.00 | 1.00 |
| chroma_step | 1.00 | 0.41 | 0.28 | 0.07 |
| block_grid | 0.53 | 1.00 | 1.00 | 0.38 |

Read the `cctv` column as the honest one. `noise_ratio` survives because the donor was blurred by
construction, so what it detects is "this region was smoothed", which is a real generator artifact
and also something a pipeline can produce on its own. `seam_edge` flips polarity between levels,
which means a threshold learned at `q75` misbehaves at `cctv`: an instability worth more attention
than any single AUC. `block_grid` separates perfectly at mid levels and dies at `cctv`, which is
what a compression witness looks like.

Null control: shuffled labels average AUC 0.498.

## What this cannot tell you

- Whether a real generator leaves this seam. The corpus is synthetic, and a GAN or a diffusion
  model has its own artifact vocabulary.
- Anything about real faces, real cameras, or footage this lab did not make.
- Whether a hit means manipulation. A hit means the number is unusual against a calibrated
  reference set, and calibration is the thing that turns this into a tool rather than a toy.

## Reproducing

```sh
python -m lab.experiment      # writes docs/lab-report.md and docs/lab-result.json
make test                     # python tests, then the case store's tests
make e2e                      # python computes, node stores, then the chain is tampered with
```
