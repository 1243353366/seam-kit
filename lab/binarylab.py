"""BinaryLab: investigate a compiled binary without its source.

The target is deliberately small. What is being tested is not the program but the method:

  1. build it from source,
  2. write an independent implementation from the specification alone,
  3. sweep inputs through both and record every divergence,
  4. read the binary's structure (symbols, call sites) as a second, independent view,
  5. inject a known bug and confirm the sweep catches it.

Step 5 is the one that matters. A differential harness that has never caught a real divergence is
a harness that agrees with itself, and that is how a reviewer ends up confirming its own
assumptions instead of the code's behaviour.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
BINARY_DIR = HERE / "binary"

#: The specification, written from the C program's documented behaviour rather than from its
#: source: total = sum(value * position), position starting at 1, and tamper when the total is a
#: multiple of seven.
WEIGHT_OFFSET = 1
TAMPER_DIVISOR = 7


def reference_total(values: list[int]) -> int:
    return sum(v * (i + WEIGHT_OFFSET) for i, v in enumerate(values))


def reference_verdict(values: list[int]) -> str:
    return "tamper" if reference_total(values) % TAMPER_DIVISOR == 0 else "clean"


def compile_source(source: Path, out: Path, cc: str = "cc") -> Path:
    if shutil.which(cc) is None:
        raise RuntimeError(f"no C compiler on PATH (looked for {cc!r})")
    subprocess.run([cc, "-O0", "-o", str(out), str(source)], check=True, capture_output=True)
    return out


def run_binary(binary: Path, values: list[int]) -> tuple[int, str]:
    proc = subprocess.run([str(binary), *map(str, values)], capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


def parse_output(stdout: str) -> tuple[int | None, str | None]:
    parts = stdout.split()
    if len(parts) != 2:
        return None, None
    try:
        return int(parts[0]), parts[1]
    except ValueError:
        return None, parts[1]


@dataclass
class Divergence:
    values: list[int]
    expected_total: int
    expected_verdict: str
    binary_total: int | None
    binary_verdict: str | None
    exit_code: int


def sweep(binary: Path, cases: list[list[int]]) -> list[Divergence]:
    out: list[Divergence] = []
    for values in cases:
        code, stdout = run_binary(binary, values)
        total, verdict = parse_output(stdout)
        want_total, want_verdict = reference_total(values), reference_verdict(values)
        if code != 0 or total != want_total or verdict != want_verdict:
            out.append(
                Divergence(
                    values=values,
                    expected_total=want_total,
                    expected_verdict=want_verdict,
                    binary_total=total,
                    binary_verdict=verdict,
                    exit_code=code,
                )
            )
    return out


def default_cases() -> list[list[int]]:
    """Small, adversarial, and cheap: negatives, zeros, a divisor hit, and a long row."""
    cases = [
        [1],
        [0],
        [-1],
        [7],
        [1, 3],
        [3, 1],
        [2, -5, 9],
        [1000000, 2000000],
        [1, 1, 1, 1, 1, 1, 1],
        list(range(-6, 7)),
    ]
    return cases


def static_view(binary: Path) -> dict:
    """Two independent structural facts, and an honest note about what they cannot show."""
    facts: dict = {"path": str(binary), "size_bytes": binary.stat().st_size}
    if shutil.which("nm"):
        nm = subprocess.run(["nm", str(binary)], capture_output=True, text=True).stdout
        facts["symbols"] = sorted(
            line.split()[-1] for line in nm.splitlines() if line.strip() and len(line.split()) == 3
        )[:20]
    if shutil.which("objdump"):
        dis = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", str(binary)], capture_output=True, text=True
        ).stdout
        facts["instructions"] = sum(1 for line in dis.splitlines() if line.strip().endswith(":") is False and "\t" in line)
        facts["calls"] = sum(1 for line in dis.splitlines() if "call" in line)
    facts["limits"] = [
        "symbols vanish under strip, so their absence is not evidence of anything",
        "instruction counts differ between compilers and optimisation levels",
        "this is structural corroboration; behaviour is established by the sweep",
    ]
    return facts


def investigate(source_name: str = "scorer.c", cc: str = "cc") -> dict:
    source = BINARY_DIR / source_name
    with tempfile.TemporaryDirectory() as tmp:
        binary = compile_source(source, Path(tmp) / "target", cc=cc)
        cases = default_cases()
        divergences = sweep(binary, cases)
        result = {
            "source": str(source),
            "cases": len(cases),
            "divergences": [d.__dict__ for d in divergences],
            "agrees_with_reference": not divergences,
            "static": static_view(binary),
        }
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="differential and structural analysis of a compiled target")
    ap.add_argument("--source", default="scorer.c")
    ap.add_argument("--cc", default="cc")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    result = investigate(args.source, cc=args.cc)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['source']}: {result['cases']} cases, {len(result['divergences'])} divergences")
        for d in result["divergences"][:5]:
            print(
                f"  input={d['values']} expected={d['expected_total']}/{d['expected_verdict']} "
                f"got={d['binary_total']}/{d['binary_verdict']}"
            )
        print("agrees with the independent implementation" if result["agrees_with_reference"] else "DISAGREES")
    return 0 if result["agrees_with_reference"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
