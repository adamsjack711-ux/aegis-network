Created the local branch `integration/cli-offline-handoff-reviewed` at **`9ba94a84fd54ea9052d09e0c73bb6c365cbd5d5d`**. It remains pinned to the exact commit tested in an isolated, clean worktree. Nothing was pushed.

I inspected its ancestry and diff first. Although neither requested input commit is an ancestor, `9ba94a8` contains patch-equivalent copies of both: the validated CLI launcher and offline packaging changes from `7f9f2a2`, and the Scout → Investigator handoff, withdrawal ordering, and tests from `9896de2`.

Using the recorded Python environment and `PYTHONPATH=src:scripts` resolved the earlier `phase4a_bench` collection error. **501 tests collected.** The full source regression finished with **463 passed, 37 skipped, 1 expected failure, 0 unexpected failures or errors**; 5 subtests also passed. The expected failure is the existing grant-file race test. `master` and the tester bundle were left untouched.
