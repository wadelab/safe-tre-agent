# Preprint

`preprint.tex` — the technical report consolidating the project: the design
(from [`docs/specification.md`](../docs/specification.md) and
[`docs/security.md`](../docs/security.md)), the red-team results, and the
planner evaluation ([`docs/planner-eval.md`](../docs/planner-eval.md)). Those
docs stay the source of truth; the paper narrates them for an external reader.

Build (needs a TeX distribution with `pdflatex` + `bibtex`):

```bash
cd paper && make        # -> preprint.pdf
make clean              # remove aux files
```

The PDF and LaTeX aux files are gitignored; attach the built PDF to a release
rather than committing it. Draft, not peer reviewed.
