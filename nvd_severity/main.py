import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

import aiofiles
from dotenv import load_dotenv

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


async def main():
    logging.basicConfig(level=logging.INFO)

    cve_path = NVD_LOCAL_REPO / "vulnerabilities"

    await load_cve(cve_path)


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()
