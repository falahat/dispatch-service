# echo — reference compute image

A minimal, dependency-free compute container that conforms to the frozen
[INVOKE contract v0](../../contracts/INVOKE.md). It exists to exercise and validate the
runner boundary: for each declared input it copies `workdir/<path>` to
`workdir/<outputs_dir>/<name>`; with no inputs it writes the invocation's `params` to
`<outputs_dir>/echo.json`. It makes no network calls, holds no credentials, and touches
only `workdir/inputs/**` (read) and `workdir/<outputs_dir>/**` (write).

`app.py` is Python 3 standard-library only (`http.server`), so the image is tiny and has no
supply chain beyond the base runtime.

## Build

    docker build -t echo-compute compute/echo

## Run

The container reads `INVOKE_ADDR` (a `host:port`) and serves HTTP/1.1 there:

    docker run -e INVOKE_ADDR=0.0.0.0:8080 -p 8080:8080 \
      -v /path/to/workdir:/work/job echo-compute

- `GET /healthz` → `200 {"ready": true, "op": "echo", "op_version": 1}` (ready at once).
- `POST /invoke` with `{job_id, invocation, workdir, inputs, outputs_dir, deadline_ts}` →
  `200 {"outputs": {...}, "metrics": {"bytes", "outputs"}}` (paths relative to workdir;
  metrics are integers). A second concurrent invoke → `409`; a past `deadline_ts` →
  `500 {"error_class": "timeout"}`; a malformed body → `500 {"error_class": "bad_input"}`.

The image ships a `fixture/` (an `invocation/v0` plus `inputs/data`) so the runner can run
the fixture invocation at boot before joining the fleet.

## Conformance

`runner check <image>` (built later) validates any compute image against the INVOKE contract
locally — healthz, fixture invoke, 409, deadline, and error mapping — the same checks CI
runs. `test.py` here runs that same suite standalone: `python compute/echo/test.py`.
