#!/usr/bin/env python3
"""Assemble one SKILL archive with Windows and Linux Native AOT binaries."""

from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def find_archive(directory: Path, rid: str) -> Path:
    archives = sorted(directory.glob(f"SNETCracker_*_{rid}.zip"))
    if len(archives) != 1:
        raise RuntimeError(f"Expected one {rid} archive in {directory}, found {len(archives)}")
    return archives[0]


def read_entry(archive: zipfile.ZipFile, filename: str) -> bytes:
    matches = [
        entry for entry in archive.infolist()
        if not entry.is_dir() and (entry.filename == filename or entry.filename.endswith("/" + filename))
    ]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one {filename} in archive, found {len(matches)}")
    return archive.read(matches[0])


def write_entry(archive: zipfile.ZipFile, filename: str, data: bytes, executable: bool = False) -> None:
    entry = zipfile.ZipInfo(filename)
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = (0o755 if executable else 0o644) << 16
    archive.writestr(entry, data)


def archive_version(archive: Path, rid: str) -> str:
    prefix = "SNETCracker_"
    suffix = f"_{rid}.zip"
    return archive.name[len(prefix):-len(suffix)]


def main() -> None:
    windows_archive = find_archive(ROOT / "pkg-win", "win-x64")
    linux_archive = find_archive(ROOT / "pkg-linux", "linux-x64")
    version = archive_version(windows_archive, "win-x64")
    linux_version = archive_version(linux_archive, "linux-x64")
    if version != linux_version:
        raise RuntimeError(f"Windows/Linux version mismatch: {version} != {linux_version}")
    output = ROOT / "dist" / f"SPasswordCheckerV2.SKILL_{version}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(windows_archive) as win, zipfile.ZipFile(linux_archive) as linux:
        config_entries = [
            entry for entry in win.infolist()
            if not entry.is_dir() and entry.filename.startswith("config/")
        ]
        if not config_entries:
            raise RuntimeError("Windows archive contains no config files")

        with zipfile.ZipFile(output, "w") as skill:
            write_entry(skill, "SKILL.md", (ROOT / "SPasswordCheckerV2.SKILL" / "SKILL.md").read_bytes())
            write_entry(skill, "bin/spc.exe", read_entry(win, "spc.exe"), executable=True)
            write_entry(skill, "bin/spc", read_entry(linux, "spc"), executable=True)
            for entry in config_entries:
                write_entry(skill, "bin/" + entry.filename, win.read(entry))

    with zipfile.ZipFile(output) as skill:
        names = skill.namelist()
        linux_mode = skill.getinfo("bin/spc").external_attr >> 16
        print(f"Created {output.relative_to(ROOT)}: {len(names)} files, {output.stat().st_size} bytes")
        print(f"Windows binary: bin/spc.exe; Linux binary: bin/spc (mode {linux_mode:o})")
        print(f"Config files: {sum(name.startswith('bin/config/') for name in names)}")


if __name__ == "__main__":
    main()
