# SmallWood LVCS leak PoC

This isolated, standard-library-only audit reproduces the retained Level-5
SmallWood subgroup collision and the resulting rank-69 witness recovery. It
does not import or edit the concurrently changing Rust engine.

From the repository root:

```sh
python3 .agent/hardening/smallwood-pqc-zk/independent-leak-audit/poc.py
python3 -m unittest discover \
  -s .agent/hardening/smallwood-pqc-zk/independent-leak-audit \
  -p 'test_*.py' -v
```

`validation_report.md` contains the source/wire trace, exact probability, and
the disjoint-coset plus leaf-tape/QROM repair assessment.
