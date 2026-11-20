"""Optional, read-only on-chain balance lookup for derived addresses.

This is the one place the wallet-recovery flow reaches the network, and only
when the operator opts in. It asks a public block explorer whether a derived
address has ever been used and what it holds, so a recovery sweep can point at
the derivation path and coin that actually have funds. It never transmits a
private key, mnemonic or seed — only public addresses the operator derived.

The lookup function is pure and injectable: tests pass a stub fetcher, so no
test ever touches the network.
"""
from __future__ import annotations

import json
import urllib.request
from urllib.parse import urlparse

# coin -> blockchair chain slug
CHAINS = {
    "bitcoin": "bitcoin",
    "litecoin": "litecoin",
    "dogecoin": "dogecoin",
    "bitcoincash": "bitcoin-cash",
    "ethereum": "ethereum",
}
DECIMALS = {"bitcoin": 8, "litecoin": 8, "dogecoin": 8, "bitcoincash": 8, "ethereum": 18}
ALLOWED_HOSTS = {"api.blockchair.com"}
MAX_LOOKUPS = 100
_READ_CAP = 1_000_000  # bytes


def _default_fetcher(url: str, timeout: int = 15) -> dict:
    """Fetch and parse JSON from an allow-listed explorer host only."""
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError("Refusing to contact a non-allow-listed host: " + host)
    request = urllib.request.Request(url, headers={"User-Agent": "CyberLab-Companion"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - host allow-listed
        return json.loads(response.read(_READ_CAP).decode("utf-8", "replace"))


def _balance_url(chain: str, address: str) -> str:
    # bitcoin-cash dashboards accept the cashaddr body without the prefix.
    query = address.split(":", 1)[1] if chain == "bitcoin-cash" and ":" in address else address
    return "https://api.blockchair.com/{chain}/dashboards/address/{addr}".format(chain=chain, addr=query)


def _parse_blockchair(payload: dict, address: str) -> tuple[int, int]:
    """Return (balance_smallest_unit, tx_count) from a blockchair address dashboard."""
    data = (payload or {}).get("data") or {}
    # The key is the queried address; fall back to the only entry when it differs.
    record = data.get(address)
    if record is None and len(data) == 1:
        record = next(iter(data.values()))
    info = (record or {}).get("address") or {}
    balance = info.get("balance", 0)
    tx_count = info.get("transaction_count", info.get("output_count", 0))
    try:
        balance = int(balance)
    except (TypeError, ValueError):
        balance = 0
    try:
        tx_count = int(tx_count)
    except (TypeError, ValueError):
        tx_count = 0
    return balance, tx_count


def _format_amount(smallest: int, coin: str) -> str:
    decimals = DECIMALS.get(coin, 8)
    whole, frac = divmod(smallest, 10 ** decimals)
    frac_str = str(frac).rjust(decimals, "0").rstrip("0")
    return "{}.{}".format(whole, frac_str) if frac_str else str(whole)


def check_balances(accounts: list[dict], fetcher=_default_fetcher, max_lookups: int = MAX_LOOKUPS) -> dict:
    """Look up each derived address's public balance and activity.

    `accounts` is a list of {"address", "coin"} dicts (as derive_accounts emits,
    minus the private key). Returns per-address results and a summary of which
    paths/coins show activity. No key material is read or sent.
    """
    if not isinstance(accounts, list) or not accounts:
        raise ValueError("Provide a non-empty list of derived accounts.")
    if not 1 <= max_lookups <= MAX_LOOKUPS:
        raise ValueError("max_lookups must be between 1 and {}.".format(MAX_LOOKUPS))

    results = []
    funded = 0
    active = 0
    for account in accounts[:max_lookups]:
        address = account.get("address")
        coin = account.get("coin")
        path = account.get("path")
        chain = CHAINS.get(coin)
        if not isinstance(address, str) or not chain:
            results.append({"address": address, "coin": coin, "path": path,
                            "status": "unsupported",
                            "note": "No supported explorer for this coin."})
            continue
        try:
            payload = fetcher(_balance_url(chain, address))
        except Exception as exc:  # network/parse failures are reported, not raised
            results.append({"address": address, "coin": coin, "path": path,
                            "status": "error", "error": str(exc)[:200]})
            continue
        balance, tx_count = _parse_blockchair(payload, address.split(":", 1)[-1])
        has_activity = tx_count > 0 or balance > 0
        if balance > 0:
            funded += 1
        if has_activity:
            active += 1
        results.append({
            "address": address, "coin": coin, "path": path, "status": "ok",
            "balance": _format_amount(balance, coin), "balance_smallest_unit": balance,
            "transaction_count": tx_count, "has_activity": has_activity,
        })
    return {
        "results": results,
        "checked": len(results),
        "funded_addresses": funded,
        "active_addresses": active,
        "note": ("Read-only public balances. Only derived addresses were sent; no key, "
                 "seed or mnemonic left this machine. Zero balance with prior activity can "
                 "still mean this is the right wallet that was later emptied."),
    }
