set -euo pipefail
set +x
umask 077
root=${1:?root required}; command=${2:?init, info or sign required}; shift 2
[[ $(id -u) != 0 && $root == /* && -d $root/dispatch ]] || exit 2
# This public topology is owner configuration, outside submitted project source.
mapfile -t settings < <(python3 - "$root" <<'PY'
import ipaddress, json, os, pathlib, re, subprocess, sys, tomllib
root = pathlib.Path(sys.argv[1])
assert root.is_absolute() and root.resolve() == root and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root))
assert root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0, 'private owned root required'
assert subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0, 'keep state outside repositories'
assert subprocess.check_output(['podman', 'info', '--format', '{{.Host.Security.Rootless}}'], text=True).strip() == 'true'
policy = tomllib.loads((root / 'dispatch/plane.toml').read_text())
for key, value in dict(db_path='/work/plane/queue.db', runner_listen='127.0.0.1:7700', app_socket='/work/plane/app.sock', app_listen='').items():
    assert policy.get(key) == value, 'backend endpoints must stay private'
config = json.loads((root / 'dispatch/plane.json').read_text())
assert config.keys() == {'address', 'runner_port', 'cas_port', 'dispatcher_image', 'auth_image', 'cas_image'}
ip = ipaddress.ip_address(config['address'])
assert any(ip in ipaddress.ip_network(net) for net in ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))
for key in ('runner_port', 'cas_port'):
    assert type(config[key]) is int and 1024 <= config[key] <= 65535
assert config['runner_port'] != config['cas_port']
for key in ('dispatcher_image', 'auth_image', 'cas_image'):
    assert re.fullmatch(r'[A-Za-z0-9_./:@+-]+', config[key])
for key in ('address', 'runner_port', 'cas_port', 'dispatcher_image', 'auth_image', 'cas_image'):
    print(config[key])
PY
)
((${#settings[@]} == 6)) || exit 2
address=${settings[0]}; port=${settings[1]}; cas_port=${settings[2]}
auth=${settings[4]}
signer() {
    podman run --rm -i --pull=never --network=none --userns=keep-id --user "$(id -u):$(id -g)" \
        --read-only --cap-drop=all --security-opt=no-new-privileges \
        -v "$root/secrets:/work/secrets:rw" --entrypoint signer "$auth" \
        -secrets /work/secrets/issuer.json -pairings /work/secrets/pairings.json "$@"
}
case $command in
    info)
        python3 - "$root" "$address:$port" "http://$address:$cas_port" <<'PY'
import json, pathlib, shlex, socket, sys
root = pathlib.Path(sys.argv[1])
print(json.dumps(dict(dispatcher=sys.argv[2], cas=sys.argv[3], kit=str(root/'dispatch/kit'),
    runner=str(root/'bin/runner'), node=socket.gethostname(),
    client=shlex.join(['env', 'PYTHONPATH='+str(root/'bin'), 'python3', '-m', 'dispatch_client.cli', '-addr', 'unix:'+str(root/'dispatch/app.sock')]),
    signer=shlex.join(['bash', str(root/'bin/plane.sh'), str(root), 'sign']))))
PY
        ;;
    sign)
        lanes=
        args=()
        while (($#)); do
            [[ $# -ge 2 ]] || exit 2
            case $1 in --lanes) lanes=$2;; --pubkey|--note) args+=("$1" "$2");; *) exit 2;; esac
            shift 2
        done
        rights=cas_get,cas_put
        if [[ -n $lanes ]]; then rights=hello,lease,heartbeat,complete,fail,release,cas_get,cas_put; fi
        signer enroll "${args[@]}" --rights "$rights" --lanes "$lanes"
        ;;
    init)
        install -d -m 700 "$root/secrets" "$root/dispatch/pep" "$root/dispatch/cas"
        pubkey=$(signer pubkey)
        if [[ ! -e $root/secrets/cas.json ]]; then
            public=$("$root/bin/runner" keygen --out "$root/secrets/cas.json")
            signer enroll --pubkey "$public" --rights cas_get,cas_put --note coordinator-cas \
                | "$root/bin/runner" seal --cred "$root/secrets/cas.json" --biscuit-file -
        fi
        printf 'http://%s:%s\n' "$address" "$cas_port" >"$root/dispatch/cas-url"
        python3 - "$root" "$pubkey" "${settings[@]}" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
root, pubkey, address, port, cas_port, dispatcher, auth, cas = sys.argv[1:]
root = pathlib.Path(root)
units = pathlib.Path(os.environ.get('XDG_CONFIG_HOME', pathlib.Path.home()/'.config'))/'containers/systemd'
units.mkdir(parents=True, exist_ok=True)
name = 'dispatch-plane-' + hashlib.sha256(str(root).encode()).hexdigest()[:12]
def write(suffix, text):
    (units/(name+suffix)).write_text(text)
write('.pod', f'[Pod]\nUserNS=keep-id\nPublishPort={address}:{port}:{port}\nPublishPort={address}:{cas_port}:{cas_port}\n')
common = f'Pod={name}.pod\nUser={os.getuid()}:{os.getgid()}\nReadOnly=true\nDropCapability=all\nNoNewPrivileges=true\n'
def container(role, image, options):
    identity = subprocess.check_output(['podman','image','inspect','--format','{{.Id}}',image], text=True).strip()
    (units/(name+'-'+role+'.container')).write_text('[Container]\nImage='+identity+'\n'+common+options+
        '\n[Service]\nRestart=on-failure\nTimeoutStopSec=infinity\n[Install]\nWantedBy=default.target\n')
container('dispatch', dispatcher, f'Entrypoint=dispatcherd\nVolume={root}/dispatch:/work/plane\nExec=-config /work/plane/plane.toml\n')
container('cas', cas, f'Volume={root}/dispatch/cas:/work/cas\nExec=--dir=/work/cas --max_size=64 --http_address=127.0.0.1:8080\n')
container('pep', auth, f'Entrypoint=pep\nVolume={root}/dispatch/pep:/work/pep\nEnvironment=PEP_ROOT_PUBKEY={pubkey}\n'
    f'Environment=PEP_RUNNER_LISTEN=0.0.0.0:{port}\nEnvironment=PEP_DISPATCHER_ADDR=127.0.0.1:7700\n'
    f'Environment=PEP_CAS_LISTEN=0.0.0.0:{cas_port}\nEnvironment=PEP_CAS_BACKEND=http://127.0.0.1:8080\n'
    'Environment=PEP_CAS_STYLE=bazel\nEnvironment=PEP_NONCE_DB=/work/pep/nonces.redb\nEnvironment=PEP_REVOCATION_DB=/work/pep/revocations.json\n')
subprocess.run(['systemctl','--user','daemon-reload'], check=True)
subprocess.run(['systemctl','--user','start',*(name+'-'+role+'.service' for role in ('dispatch','cas','pep'))], check=True)
PY
        ;;
    *) exit 2;;
esac
