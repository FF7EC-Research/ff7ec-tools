#!/usr/bin/env python3
"""Writes android-patches/patches-bundle.json for the build that's about to
be published under the `morphe-patches` release tag. Run from android-patches/
(the workflow's default working directory) with the build identified entirely
via environment variables - see .github/workflows/android-patches-release.yml.
"""
import datetime
import json
import os

mpp_name = os.environ["MPP_NAME"]
repository = os.environ["REPOSITORY"]
commit_sha = os.environ["COMMIT_SHA"]
ref_name = os.environ["REF_NAME"]

with open("patches-list.json") as f:
    version = json.load(f)["version"]

bundle = {
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "description": f"Built from {repository}@{commit_sha} ({ref_name}).",
    "download_url": f"https://github.com/{repository}/releases/download/morphe-patches/{mpp_name}",
    "signature_download_url": "",
    "version": version,
}

with open("patches-bundle.json", "w") as f:
    json.dump(bundle, f, indent=2)
    f.write("\n")

print(json.dumps(bundle, indent=2))
