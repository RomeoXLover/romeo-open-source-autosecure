from fake_useragent import UserAgent
import httpx

from securing.utils.cookies.safe_cookies import dedupe_cookies
from securing.utils.proxy import build_proxy_url


def get_session(cookies: httpx.Cookies | None = None, user_agent: str | None = None) -> httpx.AsyncClient:
    # Persistent session that handles cookies automatically.
    # Response hook collapses duplicate MSCC/etc so httpx never raises CookieConflict.
    # Each call mints a fresh sticky proxy SSID (60m) when proxy is enabled.

    async def _dedupe_hook(response: httpx.Response) -> None:
        dedupe_cookies(client)

    proxy_url = build_proxy_url()
    kwargs: dict = {}
    if proxy_url:
        # httpx 0.28+ uses `proxy=`; older used `proxies=`
        kwargs["proxy"] = proxy_url

    # Never use timeout=None — polish/SSO GETs can hang forever with no logs.
    # trust_env=False: ignore HTTP(S)_PROXY so we never silently go direct / env-proxy.
    client = httpx.AsyncClient(
        headers={
            "User-Agent": user_agent or UserAgent().random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        },
        timeout=httpx.Timeout(45.0, connect=20.0),
        cookies=cookies if cookies is not None else httpx.Cookies(),
        event_hooks={"response": [_dedupe_hook]},
        trust_env=False,
        **kwargs,
    )
    client._autosecure_proxy_url = proxy_url
    return client


def clone_session_new_proxy(old: httpx.AsyncClient) -> httpx.AsyncClient:
    """New sticky proxy exit, same Microsoft cookies.

    Dead tunnels rarely recover — get_amc was retrying 3× on the same proxy
    then wrapping ConnectError as RuntimeError so the outer secure() loop
    never rotated.
    """
    from securing.utils.secure import _copy_cookies

    ua = None
    try:
        ua = old.headers.get("User-Agent")
    except Exception:
        ua = None
    return get_session(cookies=_copy_cookies(old), user_agent=ua)
