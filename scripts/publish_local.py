#!/usr/bin/env python3
"""Build and package GUI + CLI locally with one verified version."""

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
UI_PROJECT = ROOT / "SPasswordCheckerV2" / "SPasswordCheckerV2.csproj"
CLI_PROJECT = ROOT / "SPasswordCheckerV2.Cmd" / "SPasswordCheckerV2.Cmd.csproj"


def current_rid() -> str:
    if sys.platform == "win32":
        os_name = "win"
    elif sys.platform == "darwin":
        os_name = "osx"
    elif sys.platform.startswith("linux"):
        os_name = "linux"
    else:
        raise RuntimeError(f"Unsupported local platform: {sys.platform}")
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    if os_name in ("win", "linux") and arch != "x64":
        raise RuntimeError(f"Unsupported {os_name} architecture: {arch}")
    return f"{os_name}-{arch}"


def project_value(project: Path, name: str) -> str:
    root = ET.parse(project).getroot()
    for group in root.findall("PropertyGroup"):
        value = group.findtext(name)
        if value and value.strip():
            return value.strip()
    raise RuntimeError(f"{project.relative_to(ROOT)} has no {name}")


def resolve_version(override: str | None) -> str:
    ui_version = project_value(UI_PROJECT, "Version")
    cli_version = project_value(CLI_PROJECT, "Version")
    if ui_version != cli_version:
        raise RuntimeError(f"UI/CLI version mismatch: {ui_version} != {cli_version}")
    version = override or ui_version
    if not version or any(c in version for c in "/\\"):
        raise RuntimeError(f"Invalid version: {version!r}")
    return version


def publish(project: Path, rid: str, version: str, environmental_tools: bool) -> None:
    command = [
        "dotnet", "publish", str(project.relative_to(ROOT)),
        "-c", "Release", "-r", rid, "--self-contained", "true",
        f"-p:Version={version}",
    ]
    if environmental_tools:
        command.append("-p:IlcUseEnvironmentalTools=true")
    subprocess.run(command, cwd=ROOT, check=True)


def publish_dir(project: Path, rid: str) -> Path:
    framework = project_value(project, "TargetFramework")
    return project.parent / "bin" / "Release" / framework / rid / "publish"


def verify_binary_versions(package_dir: Path, rid: str, version: str) -> None:
    suffix = ".exe" if rid.startswith("win-") else ""
    cli = package_dir / f"spc{suffix}"
    gui = package_dir / f"SPasswordCheckerV2{suffix}"
    if not cli.is_file() or not gui.is_file():
        raise RuntimeError("GUI or CLI executable is missing from the package")

    if rid == current_rid():
        result = subprocess.run([str(cli), "--version"], cwd=package_dir, check=True,
                                capture_output=True, text=True)
        actual = result.stdout.strip()
        if actual != f"spc {version}":
            raise RuntimeError(f"Packaged CLI version mismatch: {actual!r} != 'spc {version}'")
        print(f"CLI binary version verified: {actual}")

    if rid == "win-x64" and sys.platform == "win32":
        env = os.environ.copy()
        env["SPC_GUI_PATH"] = str(gui)
        result = subprocess.run([
            "powershell", "-NoProfile", "-Command",
            "(Get-Item -LiteralPath $env:SPC_GUI_PATH).VersionInfo.ProductVersion",
        ], check=True, capture_output=True, text=True, env=env)
        actual = result.stdout.strip()
        if actual != version and not actual.startswith(version + "+"):
            raise RuntimeError(f"Packaged GUI version mismatch: {actual!r} != {version!r}")
        print(f"GUI binary version verified: {actual}")


def write_zip(package_dir: Path, destination: Path, include_root: bool) -> None:
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(package_dir)
            name = Path(package_dir.name) / relative if include_root else relative
            archive.write(path, str(name).replace(os.sep, "/"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rid", default=current_rid(), help="Target RID (default: current OS/architecture)")
    parser.add_argument("--version", help="Override both project versions for this build")
    parser.add_argument("--skip-build", action="store_true", help="Package existing publish outputs")
    parser.add_argument("--check-only", action="store_true", help="Only check UI/CLI source versions")
    parser.add_argument("--ilc-environmental-tools", action="store_true",
                        help="Use MSVC/SDK tools already configured in the environment")
    parser.add_argument("--force", action="store_true", help="Replace existing local packages")
    args = parser.parse_args()

    version = resolve_version(args.version)
    print(f"Unified source version: {version}")
    if args.check_only:
        return

    output = ROOT / "dist"
    output.mkdir(parents=True, exist_ok=True)
    base = f"SNETCracker_{version}_{args.rid}"
    zip_path = output / f"{base}.zip"
    tar_path = output / f"{base}.tar.gz"
    destinations = [zip_path] if args.rid.startswith("win-") else [zip_path, tar_path]
    for destination in destinations:
        if destination.exists() and not args.force:
            raise RuntimeError(f"Package already exists: {destination}; use --force to replace it")

    if not args.skip_build:
        publish(UI_PROJECT, args.rid, version, args.ilc_environmental_tools)
        publish(CLI_PROJECT, args.rid, version, args.ilc_environmental_tools)

    ui_publish = publish_dir(UI_PROJECT, args.rid)
    cli_publish = publish_dir(CLI_PROJECT, args.rid)
    if not ui_publish.is_dir() or not cli_publish.is_dir():
        raise RuntimeError("Publish output is missing; run without --skip-build")

    with tempfile.TemporaryDirectory(prefix="local-package-", dir=output) as temp:
        package_dir = Path(temp) / base
        shutil.copytree(ui_publish, package_dir, ignore=shutil.ignore_patterns("*.pdb"))
        cli_name = "spc.exe" if args.rid.startswith("win-") else "spc"
        shutil.copy2(cli_publish / cli_name, package_dir / cli_name)
        if not args.rid.startswith("win-"):
            for name in ("SPasswordCheckerV2", "spc"):
                (package_dir / name).chmod(0o755)
        verify_binary_versions(package_dir, args.rid, version)

        for destination in destinations:
            temporary = output / f".{destination.name}.tmp"
            if destination.suffix == ".zip":
                write_zip(package_dir, temporary, include_root=not args.rid.startswith("win-"))
            else:
                with tarfile.open(temporary, "w:gz") as archive:
                    archive.add(package_dir, arcname=base)
            os.replace(temporary, destination)
            print(f"Created {destination.relative_to(ROOT)} ({destination.stat().st_size} bytes)")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Local packaging failed: {error}")
