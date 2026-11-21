"""Explicit local campaign capability. Legacy main remains backend-unavailable."""
import argparse
import os
import stat
import sys
from pathlib import Path

from .campaign import serve_campaign, serve_cleanup_probe
from .campaign_backend import DockerCampaignBackend
from .main import _read_serve_first
from .protocol import write_frame


def _private_directory(value):
    path = Path(value)
    if not path.is_absolute() or str(path) != os.path.normpath(value) or path.resolve() != path:
        raise ValueError("campaign configuration requires canonical absolute directories")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("campaign configuration directory must be private and owned")
    return path


def serve_configured(docker, staging_root, docker_config, inp=sys.stdin, out=sys.stdout,
                     backend_factory=DockerCampaignBackend):
    if sys.platform != "linux":
        raise ValueError("campaign capability requires Linux")
    root = _private_directory(staging_root)
    config = _private_directory(docker_config)
    if root == config or root in config.parents or config in root.parents:
        raise ValueError("campaign staging and Docker config directories must not overlap")
    with os.scandir(config) as entries:
        if next(entries, None) is not None:
            raise ValueError("campaign Docker config directory must be empty")
    binary = Path(docker)
    if not binary.is_absolute() or binary.resolve() != binary:
        raise ValueError("campaign Docker executable must be canonical and absolute")
    info = binary.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022 or not info.st_mode & 0o111:
        raise ValueError("campaign Docker executable is not trusted")
    first, raw = _read_serve_first(inp)
    if first is None:
        return 0
    if first.get("operation") not in ("campaign", "campaign_cleanup_probe"):
        raise ValueError("dedicated campaign entry accepts only campaign operations")
    plan = first.get("resource_plan")
    if not isinstance(plan, dict) or plan.get("staging_root") != str(root):
        raise ValueError("dedicated campaign entry requires its configured resource plan")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_CONFIG": str(config)}
    backend = backend_factory(docker=str(binary), temp_root=root, environment=environment)
    sequence = 0
    def emit(frame):
        nonlocal sequence
        sequence += 1
        frame["event_seq"] = sequence
        write_frame(out, frame)
    if first["operation"] == "campaign":
        return serve_campaign(first, inp, emit, backend=backend, first_raw=raw)
    return serve_cleanup_probe(first, emit, backend=backend, first_raw=raw)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--docker", required=True)
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--docker-config", required=True)
    args = parser.parse_args()
    return serve_configured(args.docker, args.staging_root, args.docker_config)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        sys.stderr.write("campaign configuration: " + str(exc).replace("\n", " ") + "\n")
        raise SystemExit(2)
