import asyncio
import json
import logging
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import aiofiles
from dotenv import load_dotenv

from nvd_severity.git import Git
from nvd_severity.mapper import cveMapper
from nvd_severity.nvd import NVD

load_dotenv()

NVD_LOCAL_REPO = Path(os.getenv("NVD_LOCAL_REPO", "/nvd_severity"))

# rate limits
# https://nvd.nist.gov/developers/start-here#
MAX_RATE = 3
TIME_WINDOW = 60

NVD_TOKEN = os.getenv('NVD_TOKEN')
if NVD_TOKEN:
    MAX_RATE = 10

INCREMENTAL_UPDATE = os.getenv("INCREMENTAL_UPDATE", False)


def get_required_env(key: str):
    env_var = os.getenv(key)
    if not env_var:
        raise ValueError(f"env var {key} is required")
    return env_var


GITHUB_TOKEN = get_required_env("GITHUB_TOKEN")
GITHUB_USER_NAME = get_required_env("GITHUB_USER_NAME")
GITHUB_USER_EMAIL = get_required_env("GITHUB_USER_EMAIL")

DEFAULT_REPO_OWNER = "nikpivkin"
DEFAULT_REPO_NAME = "nvd-severity"

REPO_OWNER = os.getenv("REPO_OWNER", DEFAULT_REPO_OWNER)
REPO_NAME = os.getenv("REPO_NAME", DEFAULT_REPO_NAME)
REPO_URL = f"https://{GITHUB_TOKEN}@github.com/{REPO_OWNER}/{REPO_NAME}.git"
REPO_BRANCH = os.getenv("REPO_BRANCH", "main")


async def save_vulnerability_to_file(target_path, identifier, model):
    vulnerability_file = target_path / f"{identifier}.json"

    async with aiofiles.open(vulnerability_file, "w") as f:
        await f.write(json.dumps(model, indent=2))


async def map_and_save_vulnerabilities(target_path, vulnerabilities):
    for vulnerability in vulnerabilities:
        await save_vulnerability_to_file(
            target_path,
            vulnerability["id"],
            cveMapper.map(vulnerability)
        )


async def load_cve(path):
    async with NVD(
            token=NVD_TOKEN,
            max_rate=MAX_RATE,
            time_window=TIME_WINDOW
    ) as nvd:

        if INCREMENTAL_UPDATE:
            time_of_last_update = (datetime.utcnow() - timedelta(days=2))
            await nvd.get_nvd_params(time_of_last_update=time_of_last_update)
        else:
            await nvd.get_nvd_params()

        async for vulnerabilities in nvd.get():
            await map_and_save_vulnerabilities(path, vulnerabilities)


def clone_nvd_repo(git):
    if NVD_LOCAL_REPO.exists():
        logging.info(f"Clone local {NVD_LOCAL_REPO} repo")
        git.clone(NVD_LOCAL_REPO, local=True, remote_url=REPO_URL)
    else:
        logging.info(f"Clone {REPO_URL} repo")
        git.clone(REPO_URL, local=False)


async def main():
    logging.basicConfig(level=logging.INFO)

    with tempfile.TemporaryDirectory() as tmp_dir:
        nvd_repo_path = Path(tmp_dir)

        git = Git(nvd_repo_path, GITHUB_USER_NAME, GITHUB_USER_EMAIL)
        clone_nvd_repo(git)
        git.checkout(REPO_BRANCH)

        cve_path = nvd_repo_path / "vulnerabilities"

        await load_cve(cve_path)

        git.commit(cve_path.as_posix(), "test")
        git.push(REPO_BRANCH)


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()
