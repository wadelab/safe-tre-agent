# Build the preprint. `make` -> preprint.pdf; `make clean` removes aux files.
PAPER = preprint

$(PAPER).pdf: $(PAPER).tex references.bib figures/redteam_results.png
	pdflatex -interaction=nonstopmode $(PAPER).tex
	bibtex $(PAPER)
	pdflatex -interaction=nonstopmode $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex

.PHONY: clean
clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log $(PAPER).out
