"""
Unit tests for src/gateway/core/market.py — MarketService.

All tests are hermetic: no real network calls are made.
httpx is patched via unittest.mock so AlphaVantage is never contacted.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_httpx_response(json_data: dict, status_code: int = 200):
    """Build a minimal httpx.Response-like mock."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# Tests: MarketService.get_sentiment (async)
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestMarketServiceGetSentiment:
    """Unit tests for MarketService.get_sentiment()."""

    @pytest.mark.asyncio
    async def test_no_api_key_returns_error_string(self):
        """Returns an error message string if ALPHAVANTAGE_API_KEY is not set."""
        with patch.dict("os.environ", {}, clear=True):
            # Ensure env var absent
            import os
            os.environ.pop("ALPHAVANTAGE_API_KEY", None)
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = None  # force absence
            result = await svc.get_sentiment("AAPL")

        assert "ERROR" in result
        assert "ALPHAVANTAGE_API_KEY" in result

    @pytest.mark.asyncio
    async def test_successful_sentiment_response(self):
        """Parses feed items and returns a formatted summary string."""
        feed_data = {
            "feed": [
                {
                    "title": "Market rally",
                    "overall_sentiment_score": 0.42,
                    "overall_sentiment_label": "Bullish",
                },
                {
                    "title": "Rate hike concerns",
                    "overall_sentiment_score": -0.15,
                    "overall_sentiment_label": "Bearish",
                },
            ]
        }

        mock_resp = _mock_httpx_response(feed_data)
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_async_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "test-key"
            result = await svc.get_sentiment("TSLA")

        assert "TSLA" in result
        assert "Market rally" in result
        assert "Rate hike concerns" in result
        assert "Bullish" in result
        assert "Bearish" in result

    @pytest.mark.asyncio
    async def test_no_feed_key_returns_no_news(self):
        """Returns 'No news found.' when API response has no 'feed' key."""
        mock_resp = _mock_httpx_response({"Note": None})
        # no 'feed', no 'Information', no 'Error Message'
        mock_resp.json.return_value = {}

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_async_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = await svc.get_sentiment("MSFT")

        assert "No news found" in result

    @pytest.mark.asyncio
    async def test_api_information_key_returns_api_info(self):
        """Surfaces 'API INFO:' when AlphaVantage returns an Information message."""
        data = {"Information": "Thank you for using Alpha Vantage! ..."}
        mock_resp = _mock_httpx_response(data)
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_async_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = await svc.get_sentiment("AMZN")

        assert "API INFO:" in result

    @pytest.mark.asyncio
    async def test_exception_returns_error_string(self):
        """Returns an ERROR string (does not propagate) when httpx raises."""
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.get = AsyncMock(side_effect=ConnectionError("network down"))

        with patch("httpx.AsyncClient", return_value=mock_async_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = await svc.get_sentiment("NVDA")

        assert "ERROR" in result
        assert "network down" in result


# ---------------------------------------------------------------------------
# Tests: MarketService.check_status (sync)
# ---------------------------------------------------------------------------

@pytest.mark.local
class TestMarketServiceCheckStatus:
    """Unit tests for MarketService.check_status() (synchronous)."""

    def test_no_api_key_returns_error_string(self):
        """Returns error message if ALPHAVANTAGE_API_KEY is not set."""
        from src.gateway.core.market import MarketService
        svc = MarketService()
        svc.api_key = None
        result = svc.check_status("AAPL")
        assert "ERROR" in result

    def test_successful_quote_response(self):
        """Returns OPEN status with price and change for a valid quote."""
        quote_data = {
            "Global Quote": {
                "05. price": "173.50",
                "10. change percent": "+1.23%",
            }
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = quote_data

        mock_sync_client = MagicMock()
        mock_sync_client.__enter__ = MagicMock(return_value=mock_sync_client)
        mock_sync_client.__exit__ = MagicMock(return_value=False)
        mock_sync_client.get = MagicMock(return_value=mock_resp)

        with patch("httpx.Client", return_value=mock_sync_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = svc.check_status("AAPL")

        assert "OPEN" in result
        assert "AAPL" in result
        assert "173.50" in result
        assert "+1.23%" in result

    def test_rate_limit_note_returns_limit_reached(self):
        """Returns 'LIMIT REACHED' when API returns a 'Note' (rate limit)."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"Note": "API call frequency exceeded."}

        mock_sync_client = MagicMock()
        mock_sync_client.__enter__ = MagicMock(return_value=mock_sync_client)
        mock_sync_client.__exit__ = MagicMock(return_value=False)
        mock_sync_client.get = MagicMock(return_value=mock_resp)

        with patch("httpx.Client", return_value=mock_sync_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = svc.check_status("TSLA")

        assert "LIMIT REACHED" in result

    def test_empty_global_quote_returns_closed_unknown(self):
        """Returns CLOSED/UNKNOWN when Global Quote is empty."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"Global Quote": {}}

        mock_sync_client = MagicMock()
        mock_sync_client.__enter__ = MagicMock(return_value=mock_sync_client)
        mock_sync_client.__exit__ = MagicMock(return_value=False)
        mock_sync_client.get = MagicMock(return_value=mock_resp)

        with patch("httpx.Client", return_value=mock_sync_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = svc.check_status("XYZ")

        assert "CLOSED" in result or "UNKNOWN" in result

    def test_exception_returns_error_string(self):
        """Returns ERROR string when httpx raises."""
        mock_sync_client = MagicMock()
        mock_sync_client.__enter__ = MagicMock(return_value=mock_sync_client)
        mock_sync_client.__exit__ = MagicMock(return_value=False)
        mock_sync_client.get = MagicMock(side_effect=ConnectionError("timeout"))

        with patch("httpx.Client", return_value=mock_sync_client):
            from src.gateway.core.market import MarketService
            svc = MarketService()
            svc.api_key = "key"
            result = svc.check_status("ERR")

        assert "ERROR" in result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

@pytest.mark.local
def test_market_service_module_singleton():
    """market_service module-level singleton is a MarketService instance."""
    from src.gateway.core.market import MarketService, market_service
    assert isinstance(market_service, MarketService)
