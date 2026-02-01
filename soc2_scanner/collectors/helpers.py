from typing import Any, List, Optional, Tuple

from botocore.exceptions import BotoCoreError, ClientError


def safe_call(func, *args, **kwargs) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return func(*args, **kwargs), None
    except (BotoCoreError, ClientError) as exc:
        return None, str(exc)


def format_error(service: str, region: Optional[str], error: str) -> str:
    if region:
        return f"{service}:{region}: {error}"
    return f"{service}: {error}"


def paginate_call(
    client: Any, method_name: str, result_key: str, **kwargs: Any
) -> Tuple[List[Any], Optional[str]]:
    try:
        paginator = client.get_paginator(method_name)
        items: List[Any] = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []))
        return items, None
    except (BotoCoreError, ClientError, ValueError) as exc:
        return [], str(exc)
