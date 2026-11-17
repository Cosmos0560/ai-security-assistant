"""The Phase 6 evaluation: dataset, 4-config ablation runner, metrics and the README table.

* ``dataset``      loads and checks the 120 labelled synthetic alerts (D21, D24, D34);
* ``runner``       runs them through ``pipeline.run_pipeline`` under every ``DefenseConfig`` with
                   the naive mock, and under ``all`` with the well-behaved mock (seeded);
* ``metrics``      turns a run into the metrics document, every cell with its n (D22, D23);
* ``readme_table`` renders that document as the Markdown block between the README markers (D25).

Everything is deterministic: the same dataset and seed give the same bytes.
"""
