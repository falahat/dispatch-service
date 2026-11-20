# Dispatch plane decisions

> Role: decision record (why each contract change is shaped the way it is)
> Status: current
> Updated when: a contract change adds or replaces a decision

The system design lives in easy-podcast's
[dispatch-plane document](https://github.com/falahat/easy-podcast/blob/main/docs/DISPATCH_PLANE.md).
This file records the decisions behind this repo's contract changes; each contract PR
adds its rows and cites them. A replaced decision is deleted, not struck through.

## Decisions

| ID | Contract | Decision | Why |
|---|---|---|---|
| D1 | 0.2 | An output may name a folder under `outputs/`. The runner uploads the folder's files and returns a `manifest/v0` of them, marked `kind: "manifest"` on the output. | A pose surface-prep step writes two files per video frame, about 900 for one clip. A manifest is the shape folder inputs already take, so the next step takes a folder output by address, with no copy and no new format. |
| D2 | 0.2 | `kind` on an output is optional; absent means one blob. | Action results stored before 0.2 stay valid without a migration. |
| D3 | 0.2 | The runner reads outputs only through the `outputs/` folder it created, opened as an `os.Root`. A named path outside it, a symbolic link, a file with more than one hard link, any other special file, or a replaced `outputs/` folder fails the job as `fatal`. | Outputs are untrusted compute data. Before 0.2 the runner uploaded whatever path the compute named, so a path or link could publish a file outside the workdir, such as the runner's credential, into the CAS. Retrying the same computation breaks the rule again, so the failure is fatal. |
