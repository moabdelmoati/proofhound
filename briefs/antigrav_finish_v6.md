# Antigravity — Finish the v6 dataset and retrain

Two jobs, in order. Job 1 is urgent: a Kaggle run is live now on a dataset with a data-split leak.

## Job 1 — Fix the split leak in `scripts/build_training_v6.py`

Problem: the builder writes `"split": "train"` on every row without reading the real split from
each case's `case.yaml`. 18 of 125 rows come from cases marked `split: eval` (the held-out set),
so training on them would invalidate the evaluation. Those 18 are exactly the
`"source": "distillation-v5"` rows (drawn from `benchmark/cases/`). The 107
`"source": "distillation-v1"` rows come from `training/cases/` and are correctly `split: train`.

Fix:
1. Add a module-level helper (move `import yaml` to the top of the file):
   ```python
   def case_split(case):
       for root in (TRAIN_CASES, BENCH_CASES):
           m = root / case / "case.yaml"
           if m.is_file():
               return yaml.safe_load(m.read_text(encoding="utf-8")).get("split")
       return None
   ```
2. In both `source_a` and `source_b`, replace `"split": "train"` with `"split": case_split(case)`.
3. In `main()`, after dedupe and before the token-size filter:
   ```python
   before = len(rows)
   rows = [r for r in rows if r.get("split") == "train"]
   stats["dropped non-train rows (leak guard)"] += before - len(rows)
   ```
4. Just before writing the file, add a guard:
   ```python
   assert all(r.get("split") == "train" for r in rows), "non-train row reached output"
   ```

Verify:
```
.venv/Scripts/python.exe scripts/build_training_v6.py
```
Expect ~107 rows, all `split: train`. The printed line
`prompts verified byte-for-byte against a real pipeline prompt: 8` (or more) must still appear —
do not weaken that check. Then confirm no benchmark case leaked:
```
.venv/Scripts/python.exe -c "import json;r=[json.loads(l) for l in open('training/data/harness_train_v6.jsonl',encoding='utf-8')];import pathlib;bad=[x['case'] for x in r if (pathlib.Path('benchmark/cases')/x['case']/'case.yaml').is_file() and not (pathlib.Path('training/cases')/x['case']/'case.yaml').is_file()];print('rows',len(r),'leaked',len(bad))"
```
`leaked` must be 0.

## Job 2 — Restart Kaggle training on the clean data

The live run is on bad data. Upload the fixed dataset, then push a new kernel version (which
supersedes the running one). Do the upload first:

```
cd .trash_cleanup/kaggle_v6
cp ../../training/data/harness_train_v6.jsonl harness_train.jsonl
../../.venv/Scripts/kaggle.exe datasets version -p . -m "v6 clean: train split only"
cd ../..
```
Wait until the dataset version finishes processing (check the printed URL), then:
```
cd training/train/kaggle_14b
../../../.venv/Scripts/kaggle.exe kernels push -p .
../../../.venv/Scripts/kaggle.exe kernels status ebbrewqvqv/proofhound-harness-14b-v5
cd ../../..
```

Do NOT change any setting in `training/train/kaggle_14b/kaggle_train_14b_v5.ipynb`. The
hyperparameters are deliberately identical to the v5 run so the only difference between v5 and v6
is the training data. That isolation is the whole point.

When status is `COMPLETE` (~1 hour), download the adapter:
```
.venv/Scripts/python.exe - <<'PY'
import builtins
_open=builtins.open
def o(*a,**k):
    m=k.get("mode","") or (a[1] if len(a)>1 else "r")
    if "b" not in m and "encoding" not in k: k["encoding"]="utf-8"
    return _open(*a,**k)
builtins.open=o
from kaggle.api.kaggle_api_extended import KaggleApi
api=KaggleApi();api.authenticate()
api.kernels_output("ebbrewqvqv/proofhound-harness-14b-v5",path="models/harness-adapter-14b-v6",force=True,quiet=True)
PY
```
Flatten the nested folder so `models/harness-adapter-14b-v6/adapter_config.json` is at the top,
and move the `.log` file to `.trash_cleanup/`.

## Report

Commit `scripts/build_training_v6.py` and `training/data/harness_train_v6.jsonl` to branch
`distill/v4-cloud`. Write a short note to `training/data/V6_REPORT.md`: final row count, class
spread, how many prompts were verified against real pipeline prompts, and the Kaggle run status.
Do not start any evaluation — stop after the adapter is downloaded and tell me.
