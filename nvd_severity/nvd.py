import asyncio
from contextlib import AbstractAsyncContextManager
from logging import Logger
from types import TracebackType
from typing import AsyncGenerator, Type

import aiohttp
import backoff
from aiolimiter import AsyncLimiter
from tqdm import tqdm

from nvd_severity.log import LOGGER

_MAX_TRIES = 10
_MAX_RATE = 3
_TIME_WINDOW = 60
_INTERVAL = 6  # seconds
_PAGE_SIZE = 2000


def backoff_handler(details):
    LOGGER.debug(
        "Backing off {wait:0.1f} seconds after {tries} tries".format(**details)
    )


class NVD(AbstractAsyncContextManager):

    _NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
            self,
            token=None,
            max_rate=_MAX_RATE,
            time_window=_TIME_WINDOW,
            interval=_INTERVAL,
            page_size=_PAGE_SIZE,
            logger: Logger = LOGGER.getChild("NVD")
    ):
        self._headers = {}
        if token:
            self._headers["apiKey"] = token
        self._logger = logger
        self._interval = interval
        self._page_size = page_size

        self._total_results = None
        self._start_index = 0
        self._params = {}

        self._rate_limiter = AsyncLimiter(max_rate, time_window)
        connector = aiohttp.TCPConnector(limit_per_host=max_rate)
        self._session = aiohttp.ClientSession(connector=connector, trust_env=True, headers=self._headers)

    async def _get_nvd_params(self):

        self._params["startIndex"] = 0
        self._params["resultsPerPage"] = 1

        await self._request()

        self._params["resultsPerPage"] = self._page_size
        self._logger.info(f"Total {self._total_results} entries found")

    @backoff.on_exception(
        backoff.expo,
        aiohttp.ClientError,
        max_tries=_MAX_TRIES,
        on_backoff=backoff_handler
    )
    async def _request(self, start_index=0):
        params = self._params | {"startIndex": start_index}
        async with self._rate_limiter:
            async with self._session.get(
                    self._NVD_API,
                    params=params,
                    raise_for_status=True
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if start_index == 0:
                        self._total_results = data["totalResults"]
                        self._start_index = data["startIndex"]
                    vulnerabilities = [v["cve"] for v in data["vulnerabilities"]]
                    await asyncio.sleep(self._interval)
                    return vulnerabilities

    async def get(self) -> AsyncGenerator:
        await self._get_nvd_params()

        indexes = range(self._start_index, self._total_results, self._page_size)
        nvd_requests = list(map(self._request, indexes))

        total_tasks = len(nvd_requests)
        for task in tqdm(
            asyncio.as_completed(nvd_requests),
            desc="Fetching vulnerabilities",
            total=total_tasks,
        ):
            vulnerabilities = await task
            yield vulnerabilities

    async def __aenter__(self) -> "NVD":
        return self

    async def __aexit__(
            self,
            __exc_type: Type[BaseException] | None,
            __exc_value: BaseException | None,
            __traceback: TracebackType | None
    ) -> None:
        await self._session.close()
