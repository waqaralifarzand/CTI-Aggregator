import asyncio

import httpx


class ConnectorError(Exception):
    """Raised when a feed connector encounters an unrecoverable error."""
    pass


async def with_retry(func, *args, max_retries: int = 3, backoff_base: int = 2, **kwargs):
    """Exponential backoff retry for async HTTP calls.

    Only retries on timeouts and server errors (5xx). Client errors (4xx) are
    raised immediately.
    """
    last_exception = None
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except httpx.TimeoutException as e:
            last_exception = e
            wait = backoff_base ** attempt
            await asyncio.sleep(wait)
        except httpx.HTTPStatusError as e:
            if e.response.status_code < 500:
                raise
            last_exception = e
            wait = backoff_base ** attempt
            await asyncio.sleep(wait)
    raise ConnectorError(f"Failed after {max_retries} retries") from last_exception
