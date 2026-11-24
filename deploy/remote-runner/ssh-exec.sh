#!/bin/bash
# A command runner's installed command that runs each job on another machine over SSH, for a machine that must never
# connect to the plane: the runner drives it, and it only answers.
#
#   The runner's COMMAND, on its own machine:   ssh-exec.sh drive SSH_CONFIG HOST
#   The other machine, as the key's forced command in its authorized_keys:
#     restrict,command="ssh-exec.sh serve WORK COMMAND [ARG...]" ssh-ed25519 ...
#
# drive sends the job's inputs/ to HOST, runs COMMAND there in WORK/JOB with the runner's stdin (its workdir rewritten)
# and GPU grant, streams the command's output into the job log, brings back outputs/ and invoke-result.json (or
# invoke-failure.json) when it exits 0, and deletes WORK/JOB. On SIGTERM it stops the remote command first and waits
# for it. serve answers only nvidia-smi --query-...=/--format=... (the runner reads HOST's GPUs through a --nvidia-smi
# wrapper), the blob cache's have and put, and link, run, stop, get and drop of one job folder; it runs no command but
# its own, and both ends unpack only regular files and folders. Progress files are not relayed.
#
# HOST keeps every input and output file it has held in WORK/.cache, named by its sha256, so a file crosses once: the
# same code, or a step's outputs as the next step's inputs, are not sent again. `ssh-exec.sh send SSH_CONFIG HOST JOB`
# (drive's first step) asks HOST which of ./inputs it lacks and sends only those, spread over SSH_EXEC_STREAMS
# (default 8) separate connections, since one connection to a far machine carries far less than the link (to the pose
# VM, 2026-11-20: 0.33 MB/s on one, 0.8 MB/s on 4, 1.4-1.5 MB/s on 8 of a 1.75 MB/s uplink); then HOST copies the
# job's files from its cache, so a command that rewrites an input changes only its own copy. Its outputs join the cache
# as copies too, so a process the command leaves running that writes one later changes only the job's file. drop keeps
# the cache under SSH_EXEC_CACHE_MB (default 10240), least recently used first.
set -euo pipefail
streams=${SSH_EXEC_STREAMS:-8}
[[ $streams =~ ^[1-9][0-9]?$ ]] || { echo "ssh-exec: SSH_EXEC_STREAMS must be 1 to 99" >&2; exit 2; }
untar='import sys, tarfile
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
    for member in archive:
        if not (member.isreg() or member.isdir()):
            sys.exit("ssh-exec: refusing %s, not a regular file or folder" % member.name)
        archive.extract(member, sys.argv[1], filter="data")'
blobs=$(cat << 'EOF'
import hashlib, json, os, re, shutil, stat, subprocess, sys, tarfile, tempfile, threading, time
verb, args = sys.argv[1], sys.argv[2:]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def blob(cache, digest):
    if not re.fullmatch("[0-9a-f]{64}", digest):
        sys.exit("ssh-exec: bad blob name")
    return os.path.join(cache, digest)


# Copy a stream into a new read-only file in the cache, returning its path and the sha256 of what was copied: a file
# joins the cache under the hash of the bytes stored, whatever its source does meanwhile.
def take(cache, source):
    fd, part = tempfile.mkstemp(prefix=".in-", dir=cache)
    h = hashlib.sha256()
    with os.fdopen(fd, "wb") as out:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            h.update(chunk)
            out.write(chunk)
    os.chmod(part, 0o444)
    return part, h.hexdigest()


def pack(pipe, files):
    try:
        with tarfile.open(fileobj=pipe, mode="w|") as archive:
            for digest, path in files:
                archive.add(path, arcname=digest, recursive=False)
    finally:
        pipe.close()


if verb == "send":  # ./inputs to HOST's folder JOB: index it, send what HOST lacks over STREAMS connections, link
    config, host, job, streams = args
    index, sizes = [], {}
    for root, dirs, names in os.walk("inputs"):
        for name in dirs + names:
            path = os.path.join(root, name)
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                index.append({"path": path, "dir": True})
            elif stat.S_ISREG(st.st_mode):
                index.append({"path": path, "sha256": sha256(path), "exec": bool(st.st_mode & 0o100)})
                sizes[index[-1]["sha256"]] = (st.st_size, path)
            else:
                sys.exit("ssh-exec: %s is not a regular file or folder" % path)
    lines = "".join(json.dumps(entry) + "\n" for entry in index).encode()
    ssh = ["ssh", "-F", config]
    missing = subprocess.run(ssh + [host, "have"], input=lines, stdout=subprocess.PIPE, check=True).stdout.split()
    loads = [[0, []] for _ in range(int(streams))]
    for digest in sorted({d.decode() for d in missing}, key=lambda d: -sizes[d][0]):
        least = min(loads, key=lambda load: load[0])
        least[0] += sizes[digest][0]
        least[1].append((digest, sizes[digest][1]))
    sending = []
    for _, files in loads:
        if files:
            put = subprocess.Popen(ssh + ["-o", "ControlPath=none", host, "put"], stdin=subprocess.PIPE)
            writer = threading.Thread(target=pack, args=(put.stdin, files))
            writer.start()
            sending.append((put, writer))
    failed = False
    for put, writer in sending:
        writer.join()
        failed |= put.wait() != 0
    if failed:
        sys.exit("ssh-exec: sending inputs failed")
    subprocess.run(ssh + [host, "link", job], input=lines, check=True)
elif verb == "have":  # the index on stdin: print each blob the cache lacks, once; mark the rest as just used
    cache, = args
    asked = set()
    for line in sys.stdin:
        digest = json.loads(line).get("sha256")
        if digest is not None and digest not in asked:
            asked.add(digest)
            try:
                os.utime(blob(cache, digest))
            except FileNotFoundError:
                print(digest)
elif verb == "put":  # a tar of files named by their sha256 on stdin: each joins the cache once its content matches
    cache, = args
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        for member in archive:
            final = blob(cache, member.name)
            if not member.isreg():
                sys.exit("ssh-exec: refusing %s, not a regular file" % member.name)
            part, digest = take(cache, archive.extractfile(member))
            if digest != member.name:
                os.unlink(part)
                sys.exit("ssh-exec: %s does not hash to its name" % member.name)
            os.replace(part, final)
elif verb == "link":  # the index on stdin: build the job folder anew from copies of the cache's files. A hard link
    # would let a command that writes an input in place (as root, or after a chmod) change it under every later job.
    cache, job = args
    if os.path.lexists(job):
        shutil.rmtree(job)
    os.mkdir(job, 0o700)
    for line in sys.stdin:
        entry = json.loads(line)
        parts = entry["path"].split("/")
        if parts[0] != "inputs" or any(part in ("", ".", "..") for part in parts):
            sys.exit("ssh-exec: refusing path %r" % entry["path"])
        path = os.path.join(job, *parts)
        if entry.get("dir"):
            os.makedirs(path, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copyfile(blob(cache, entry["sha256"]), path)
        os.chmod(path, 0o700 if entry.get("exec") else 0o600)  # the owner's, as the runner lays out inputs itself
elif verb == "keep":  # the job's regular output files join the cache too, so a next step's inputs need not cross. Each
    # is copied in: a hard link would let a process the command left running write the file later, changing the cached
    # file under its old name for every later job.
    cache, job = args
    for root, _, names in os.walk(os.path.join(job, "outputs")):
        for name in names:
            path = os.path.join(root, name)
            if stat.S_ISREG(os.lstat(path).st_mode):
                with open(path, "rb") as source:
                    part, digest = take(cache, source)
                os.replace(part, blob(cache, digest))
elif verb == "prune":  # least recently used first, until the cache holds at most LIMIT MB; stale partial files go
    cache, limit = args
    held, now = [], time.time()
    for entry in os.scandir(cache):
        st = entry.stat(follow_symlinks=False)
        if entry.name.startswith(".in-"):
            if now - st.st_mtime > 3600:
                os.unlink(entry.path)
        else:
            held.append((st.st_mtime, st.st_size, entry.path))
    total = sum(size for _, size, _ in held)
    for _, size, path in sorted(held):
        if total <= int(limit) << 20:
            break
        os.unlink(path)
        total -= size
EOF
)
grant='NVIDIA_VISIBLE_DEVICES|CUDA_VISIBLE_DEVICES|DISPATCH_GPU_INDEX|DISPATCH_GPU_UUID|DISPATCH_GPU_MEMORY_MB|DISPATCH_GPU_MODE|DISPATCH_RUNNER_ID|DISPATCH_RUNNER_NODE'
case ${1:-} in
send) exec python3 -c "$blobs" send "$2" "$3" "$4" "$streams" ;;
drive)
  config=$2 host=$3
  request=$(cat)
  id=$(printf '%s' "$request" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
  remote() { ssh -F "$config" "$host" "$@"; }
  vars=()
  for v in ${grant//|/ }; do [ -z "${!v+x}" ] || vars+=("$v=${!v}"); done
  python3 -c "$blobs" send "$config" "$host" "$id" "$streams" || { remote drop "$id" || true; exit 1; }
  printf '%s' "$request" | remote run "$id" "${vars[@]}" &
  job=$!
  trap 'until remote stop "$id" || ! kill -0 "$job" 2> /dev/null; do sleep 1; done' TERM INT
  rc=0; wait "$job" || rc=$?
  while kill -0 "$job" 2> /dev/null; do rc=0; wait "$job" || rc=$?; done
  [ "$rc" != 0 ] || remote get "$id" | python3 -c "$untar" . || rc=$?
  remote drop "$id" || true
  exit "$rc" ;;
serve)
  work=$2; shift 2
  cache=$work/.cache; mkdir -p "$cache"
  read -r -a words <<< "${SSH_ORIGINAL_COMMAND:-}"
  verb=${words[0]:-} id=${words[1]:-}
  case $verb in
  nvidia-smi)
    for a in "${words[@]:1}"; do [[ $a =~ ^--(query-gpu|query-compute-apps|format)=[a-z_.,]+$ ]] || exit 2; done
    exec nvidia-smi "${words[@]:1}" ;;
  have|put) [ ${#words[@]} = 1 ] || exit 2; exec python3 -c "$blobs" "$verb" "$cache" ;;
  esac
  [[ $id =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "ssh-exec: bad job id" >&2; exit 2; }
  dir=$work/$id
  case $verb in
  link) exec python3 -c "$blobs" link "$cache" "$dir" ;;
  run)
    for kv in "${words[@]:2}"; do [[ $kv =~ ^($grant)=[A-Za-z0-9_.:,-]*$ ]] || exit 2; export "${kv?}"; done
    cd "$dir"; mkdir -p outputs
    python3 -c 'import json, sys; j = json.load(sys.stdin); j["workdir"] = sys.argv[1]; json.dump(j, sys.stdout)' "$dir" > request.json
    export DISPATCH_WORKDIR=$dir DISPATCH_PROGRESS_FILE=$dir/invoke-progress.json
    echo $$ > run.pid
    exec "$@" < request.json ;;
  stop)
    pid=$(cat "$dir/run.pid"); kill -TERM "$pid" 2> /dev/null || true
    while kill -0 "$pid" 2> /dev/null; do sleep 1; done ;;
  get)
    python3 -c "$blobs" keep "$cache" "$dir" || true; cd "$dir"
    said=(); for f in invoke-result.json invoke-failure.json; do [ ! -f "$f" ] || said+=("$f"); done
    exec tar -cf - outputs "${said[@]}" ;;
  drop) rm -rf -- "$dir"; exec python3 -c "$blobs" prune "$cache" "${SSH_EXEC_CACHE_MB:-10240}" ;;
  *) echo "ssh-exec: unknown request" >&2; exit 2 ;;
  esac ;;
*) echo "usage: ssh-exec.sh drive SSH_CONFIG HOST | send SSH_CONFIG HOST JOB | serve WORK COMMAND [ARG...]" >&2; exit 2 ;;
esac
