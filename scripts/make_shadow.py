"""Write shadow data for a dataset definition.

Shadow data carry the real study's column names, types and declared value
domains and none of its content — see `safetre/shadow.py` for why that is safe
and what it is consequently useless for. The output is CSVs a researcher can
open in JASP, SPSS, R or a spreadsheet to get an analysis roughly working
before submitting the finished spec to the gateway.

    # the packaged demo study
    uv run python scripts/make_shadow.py --out shadow/

    # a real operator definition, with a realistic events table and two
    # psychometrics put on their true scales
    uv run python scripts/make_shadow.py \\
        --dataset /etc/safetre/study.yaml --out /srv/shadow \\
        --persons 2000 --rows events=40000 \\
        --range pgsi_score=0:27 --range wemwbs_score=14:70 \\
        --derive age_band=age_years

Nothing here reads participant data; the only input is the definition file.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from safetre import dataset as _dataset          # noqa: E402
from safetre.shadow import (                     # noqa: E402
    FALLBACK_RANGE, ShadowError, shadow_from_definition, write_shadow,
)


def _pairs(values, what, cast):
    out = {}
    for item in values or ():
        key, sep, rest = item.partition("=")
        if not sep:
            raise SystemExit(f"--{what} expects name=value, got {item!r}")
        try:
            out[key] = cast(rest)
        except ValueError as exc:
            raise SystemExit(f"--{what} {item!r}: {exc}") from exc
    return out


def _interval(text: str) -> tuple[float, float]:
    lo, sep, hi = text.partition(":")
    if not sep:
        raise ValueError("expects lo:hi")
    return float(lo), float(hi)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", metavar="PATH",
                        help="dataset definition YAML (default: the packaged demo)")
    parser.add_argument("--out", default="shadow", metavar="DIR",
                        help="output directory (default: shadow/)")
    parser.add_argument("--persons", type=int, default=500,
                        help="number of distinct people (default: 500)")
    parser.add_argument("--seed", type=int, default=0,
                        help="generator seed (default: 0); the same seed and "
                             "definition always give the same files")
    parser.add_argument("--rows", action="append", metavar="TABLE=N",
                        help="rows for one base table; repeatable. Default is "
                             "one row per person for tables carrying the person "
                             "key, so event tables usually want this set")
    parser.add_argument("--range", action="append", metavar="COL=LO:HI",
                        dest="ranges", help="bounds for a numeric column the "
                        "definition does not bound; repeatable. Without it "
                        f"such columns are uniform on {FALLBACK_RANGE[0]:g}-"
                        f"{FALLBACK_RANGE[1]:g} and flagged in the README")
    parser.add_argument("--derive", action="append", metavar="BAND=SOURCE",
                        dest="derives", help="compute a banded column from the "
                        "numeric column it bands (e.g. age_band=age_years); "
                        "repeatable. Without it the two are drawn independently "
                        "and will disagree. Never inferred: the band edges and "
                        "the labels must both be declared, and must agree")
    args = parser.parse_args()

    defn = (_dataset.load_dataset(args.dataset) if args.dataset
            else _dataset.load_dataset(_dataset._PACKAGED))

    try:
        shadow = shadow_from_definition(
            defn,
            n_persons=args.persons,
            seed=args.seed,
            rows=_pairs(args.rows, "rows", int),
            ranges=_pairs(args.ranges, "range", _interval),
            derive=_pairs(args.derives, "derive", str),
        )
    except ShadowError as exc:
        print(f"cannot build a shadow of {defn.name!r}:\n  {exc}", file=sys.stderr)
        return 1

    written = write_shadow(shadow, args.out)
    out = pathlib.Path(args.out)
    print(f"shadow of {defn.name!r} (seed {shadow.seed}) -> {out}/")
    for name, frame in sorted(shadow.datasets.items()):
        print(f"  {name + '.csv':<28} {len(frame):>7} rows  "
              f"{len(frame.columns)} columns")
    print(f"  base/ + README.md + MANIFEST.json   ({len(written)} files)")
    if shadow.fallbacks:
        print(f"\n  no declared scale, uniform on {FALLBACK_RANGE[0]:g}-"
              f"{FALLBACK_RANGE[1]:g}: {', '.join(sorted(shadow.fallbacks))}")
        print("  give them real bounds with --range col=lo:hi")
    return 0


if __name__ == "__main__":
    sys.exit(main())
