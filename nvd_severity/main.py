import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Literal

import aiofiles
from dotenv import load_dotenv

from nvd_severity.nvd import NVD

load_dotenv()

VULNERABILITIES = Path.cwd() / "vulnerabilities"

# rate limits
# https://nvd.nist.gov/developers/start-here#
MAX_RATE = 3
TIME_WINDOW = 60

NVD_TOKEN = os.getenv('NVD_TOKEN')
if NVD_TOKEN:
    MAX_RATE = 10


def get_cvss_by_source_type(source_type: Literal['Primary', 'Secondary'], cvss_list):
    return next(filter(lambda x: x["type"] == source_type, cvss_list), None)


def extract_severity(cve) -> str:

    metrics = cve.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV3", metrics.get("cvssMetricV2"))
    if cvss_list:
        cvss = get_cvss_by_source_type("Primary", cvss_list)
        if cvss is None:
            cvss = get_cvss_by_source_type("Secondary", cvss_list)
        return cvss.get("baseSeverity")

    return "UNKNOWN"


def extract_description(cve) -> str:
    return [d["value"] for d in cve["descriptions"] if d["lang"] == "en"][0]


async def save_vulnerability_to_file(identifier, model):
    vulnerability_file = VULNERABILITIES / f"{identifier}.json"

    async with aiofiles.open(vulnerability_file, "w") as f:
        await f.write(json.dumps(model, indent=2))


async def map_and_save_vulnerabilities(vulnerabilities):
    for vulnerability in vulnerabilities:

        model = {
            "Description": extract_description(vulnerability),
            "Severity": extract_severity(vulnerability)
        }

        await save_vulnerability_to_file(
            vulnerability["id"],
            model
        )


async def main():
    logging.basicConfig(level=logging.DEBUG)
    VULNERABILITIES.mkdir(exist_ok=True)

    async with NVD(
            token=NVD_TOKEN,
            max_rate=MAX_RATE,
            time_window=TIME_WINDOW
    ) as nvd:
        async for vulnerabilities in nvd.get():
            await map_and_save_vulnerabilities(vulnerabilities)


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()
