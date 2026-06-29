"""Generate the synthetic behavioural dataset into ./data."""

import argparse

from safetre import synth


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--donors", type=int, default=500)
    ap.add_argument("--out", default="data")
    args = ap.parse_args()

    tables = synth.generate(seed=args.seed, n_donors=args.donors)
    synth.save_csvs(tables, args.out)
    for name, df in tables.items():
        print(f"  {name:8s} {len(df):6d} rows  ->  {args.out}/{name}.csv")


if __name__ == "__main__":
    main()
