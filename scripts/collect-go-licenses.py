# SPDX-License-Identifier: MIT
"""Copy module license and notice files for the release's Go target."""

import shutil
import subprocess
import sys
from pathlib import Path


def collect(target):
    template = '{{with .Module}}{{if .Version}}{{.Path}}@{{.Version}}{{"\\t"}}{{.Dir}}{{end}}{{end}}'
    listing = subprocess.check_output(
        ["go", "list", "-deps", "-tags", "taggedpdf", "-f", template, "."], text=True,
    )
    modules = dict(line.split("\t", 1) for line in listing.splitlines() if line)
    if not modules:
        raise RuntimeError("The release build did not report any Go dependencies")

    for module, source in sorted(modules.items()):
        files = [
            path for path in Path(source).iterdir()
            if path.is_file() and path.name.upper().startswith(
                ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE")
            )
        ]
        if not files:
            raise RuntimeError(f"No module license or notice found for {module}")
        destination = target / module
        destination.mkdir(parents=True, exist_ok=True)
        for path in files:
            shutil.copyfile(path, destination / path.name)

    shutil.copyfile(Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()) / "LICENSE",
                    target / "Go-LICENSE.txt")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: collect-go-licenses.py LICENSE_DIR")
    collect(Path(sys.argv[1]))
