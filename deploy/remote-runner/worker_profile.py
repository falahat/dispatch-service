"""One validator and renderer for public worker installation profiles."""

import ipaddress, json, pathlib, re, shlex, shutil, sys


def render(source, environment, stage, native):
    config = {}
    for line in environment.read_text().splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if len(words) != 1 or "=" not in words[0]:
            raise ValueError(
                "use one quoted KEY=value assignment per line; no shell code or secrets"
            )
        key, value = words[0].split("=", 1)
        if key in config:
            raise ValueError("duplicate setting")
        config[key] = value
    required = (
        {
            "NAME",
            "DISPATCHER_ADDR",
            "CAS_URL",
            "LANES",
            "RUNNER_NODE",
            "WORK_ROOT",
            "COMMAND",
            "COUNT",
        }
        if native
        else {
            "NAME",
            "RUNNER_IMAGE",
            "COMPUTE_IMAGE",
            "PLANE_ADDR",
            "LANES",
            "GPU",
            "MODEL_EGRESS",
            "MEMORY",
            "CPUS",
        }
    )
    optional = (
        {"NO_DEADLINE"}
        if native
        else {
            "SMOKESCREEN_IMAGE",
            "MODEL_SUBNET",
            "COMPUTE_ENV",
            "COMPUTE_SECRETS",
            "COMPUTE_ARGS",
            "RUNNER_NODE",
        }
    )
    if required - config.keys() or config.keys() - required - optional:
        raise ValueError("missing or unknown remote-runner settings")
    if any(any(ord(c) < 32 or c == "%" for c in value) for value in config.values()):
        raise ValueError(
            "settings may not contain control characters or systemd specifiers"
        )
    if not re.fullmatch(r"[a-z][a-z0-9-]*", config["NAME"]):
        raise ValueError("NAME must be a lowercase application identifier")
    config["MODE"] = "command" if native else "http"
    config.setdefault("COUNT", "1")
    (stage / "name").write_text(config["NAME"] + "\n")
    if native:
        if not 1 <= int(config["COUNT"]) <= 64 or not all(
            re.fullmatch(r"[a-z0-9-]{1,32}", lane)
            for lane in config["LANES"].split(",")
        ):
            raise ValueError("invalid instance count or lanes")
        config["COUNT"] = str(int(config["COUNT"]))
        command = shlex.split(config["COMMAND"])
        if (
            not pathlib.Path(config["WORK_ROOT"]).is_absolute()
            or not command
            or not pathlib.Path(command[0]).is_absolute()
            or config.get("NO_DEADLINE", "0") not in ("0", "1")
        ):
            raise ValueError(
                "absolute work root/executable and valid deadline setting required"
            )
        args = [
            "run",
            "--credential",
            "@BASE@/cred/%i.json",
            "--dispatcher",
            config["DISPATCHER_ADDR"],
            "--cas",
            config["CAS_URL"],
            "--node",
            config["RUNNER_NODE"],
            "--lanes",
            config["LANES"],
            "--work",
            config["WORK_ROOT"],
        ]
        if config.get("NO_DEADLINE") == "1":
            args += ["--no-deadline"]
        text = (source / "command.service").read_text()
        (stage / "runner.service").write_text(
            text.replace(
                "@COMMAND_ARGS@",
                " ".join(json.dumps(arg) for arg in [*args, "--", *command]),
            )
        )
        (stage / "profile.json").write_text(json.dumps(config))
        return config
    if not re.fullmatch(r"[1-9][0-9]*[kKmMgGtT]?", config["MEMORY"]):
        raise ValueError("MEMORY requires a positive Podman size")
    if not re.fullmatch(
        r"(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)", config["CPUS"]
    ):
        raise ValueError("CPUS requires a positive CPU count")
    for name in ("RUNNER_IMAGE", "COMPUTE_IMAGE", "SMOKESCREEN_IMAGE"):
        if name in config and not re.fullmatch(r"[A-Za-z0-9_./:@+-]+", config[name]):
            raise ValueError("use a container image reference")
    if not re.fullmatch(
        r"[A-Za-z0-9_.:\[\]-]+", config["PLANE_ADDR"]
    ) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*", config["LANES"]):
        raise ValueError("invalid plane address or lane names")
    if config["GPU"] not in ("0", "1") or config["MODEL_EGRESS"] not in ("0", "1"):
        raise ValueError("GPU and MODEL_EGRESS must be 0 or 1")
    if config["MODEL_EGRESS"] == "0":
        config.pop("SMOKESCREEN_IMAGE", None)
        config.pop("MODEL_SUBNET", None)
    config.setdefault("RUNNER_NODE", config["NAME"] + "-%H")
    options = []
    if config["GPU"] == "1":
        options += [
            "AddDevice=nvidia.com/gpu=all",
            "Volume=/var/lib/tailworker/locks:/var/lib/tailworker/locks:ro",
            "Environment=GPU_LOCK_DIR=/var/lib/tailworker/locks",
        ]
    if config["MODEL_EGRESS"] == "1":
        if not config.get("SMOKESCREEN_IMAGE") or not config.get("MODEL_SUBNET"):
            raise ValueError(
                "model egress requires SMOKESCREEN_IMAGE and a distinct MODEL_SUBNET"
            )
        if not ipaddress.ip_network(config["MODEL_SUBNET"], strict=True).is_private:
            raise ValueError("model subnet must be private")
        options += [
            "Network=" + config["NAME"] + "-model.network",
            "Volume=" + config["NAME"] + "-model-cache.volume:/cache:U",
            "Environment=HTTP_PROXY=http://" + config["NAME"] + "-smokescreen:4750",
            "Environment=HTTPS_PROXY=http://" + config["NAME"] + "-smokescreen:4750",
            "Environment=HF_HOME=/cache",
        ]
    for value in shlex.split(config.get("COMPUTE_ENV", "")):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.+", value):
            raise ValueError("COMPUTE_ENV contains public KEY=value settings only")
        options.append("Environment=" + json.dumps(value))
    for value in shlex.split(config.get("COMPUTE_SECRETS", "")):
        if not re.fullmatch(r"[A-Za-z0-9_.=,/-]+", value):
            raise ValueError(
                "COMPUTE_SECRETS contains Podman secret names and mount options only"
            )
        options.append("Secret=" + value)
    if config.get("COMPUTE_ARGS"):
        options.append(
            "Exec="
            + " ".join(
                json.dumps(value) for value in shlex.split(config["COMPUTE_ARGS"])
            )
        )
    config["COMPUTE_OPTIONS"] = "\n".join(options)
    for path in source.iterdir():
        if path.suffix not in (".container", ".network", ".volume"):
            continue
        if "model" in path.name or "smokescreen" in path.name:
            if config["MODEL_EGRESS"] != "1":
                continue
        text = path.read_text()
        for name, value in config.items():
            text = text.replace("@" + name + "@", value)
        if re.search(r"@[A-Z_]+@", text):
            raise ValueError("unresolved unit placeholder")
        (stage / path.name.replace("plane-", config["NAME"] + "-", 1)).write_text(text)
    (stage / "profile.json").write_text(json.dumps(config))
    (stage / "images").write_text(
        "\n".join(
            config[key]
            for key in ("RUNNER_IMAGE", "COMPUTE_IMAGE", "SMOKESCREEN_IMAGE")
            if config.get(key)
        )
        + "\n"
    )
    if config["MODEL_EGRESS"] == "1":
        shutil.copytree(
            source.parent / "smokescreen",
            stage / "smokescreen",
            ignore=shutil.ignore_patterns("*.go", "go.*", "Dockerfile"),
        )
    return config


if __name__ == "__main__":
    render(*map(pathlib.Path, sys.argv[1:4]), bool(sys.argv[4]))
