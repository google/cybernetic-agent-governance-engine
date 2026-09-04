# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os

import httpx

logger = logging.getLogger(__name__)


class MarketService:
    def __init__(self):  # type: ignore[no-untyped-def]
        self.api_key = os.getenv("ALPHAVANTAGE_API_KEY")
        self.base_url = "https://www.alphavantage.co/query"

    async def get_sentiment(self, symbol: str) -> str:
        """
        Fetches market sentiment and news for a ticker using AlphaVantage.
        """
        if not self.api_key:
            return "ERROR: ALPHAVANTAGE_API_KEY not set. Cannot fetch sentiment."

        try:
            params = {
                "function": "NEWS_SENTIMENT",
                "tickers": symbol,
                "apikey": self.api_key,
                "limit": 5,
            }
            logger.info(f"Fetching AlphaVantage sentiment for {symbol}...")

            async with httpx.AsyncClient() as client:
                response = await client.get(self.base_url, params=params, timeout=10.0)  # type: ignore[arg-type]
                response.raise_for_status()
                data = response.json()

            if "feed" not in data:
                # Handle cases where API returns error (e.g. rate limit)
                if "Information" in data:
                    return f"API INFO: {data['Information']}"
                if "Error Message" in data:
                    return f"API ERROR: {data['Error Message']}"
                return "No news found."

            # Summarize the news
            summary = [f"Market Sentiment for {symbol}:"]

            for item in data.get("feed", []):
                title = item.get("title", "No Title")
                score = item.get("overall_sentiment_score", 0)
                label = item.get("overall_sentiment_label", "Neutral")
                summary.append(f"- [{label} ({score})] {title}")

            return "\n".join(summary)

        except Exception as e:
            logger.error(f"AlphaVantage Error: {e}")
            return f"ERROR: Failed to fetch sentiment: {e}"

    def check_status(self, symbol: str) -> str:
        """
        Fetches real market status and price using AlphaVantage (Global Quote).
        API usage: 1 call.
        """
        # Synchronous wrapper or implementation using httpx (sync) or requests if available.
        # Since this method is called synchronously by legacy gRPC tools, we might need requests or sync httpx.
        # But we removed requests frompyproject.toml? No, httpx is there.
        # Using httpx.Client() for sync.

        if not self.api_key:
            return "ERROR: ALPHAVANTAGE_API_KEY not set."

        try:
            params = {
                "function": "GLOBAL_QUOTE",
                "symbol": symbol,
                "apikey": self.api_key,
            }

            with httpx.Client() as client:
                response = client.get(self.base_url, params=params, timeout=10.0)
                data = response.json()

            # Rate Limit Check
            if "Note" in data:
                return f"LIMIT REACHED: {data['Note']}"

            quote = data.get("Global Quote", {})
            if not quote:
                return f"CLOSED/UNKNOWN: Could not fetch price for {symbol}"

            price = quote.get("05. price")
            change = quote.get("10. change percent")

            return f"OPEN: {symbol} trading at ${price} ({change})"

        except Exception as e:
            logger.error(f"Market Data Error: {e}")
            return f"ERROR: Market data unavailable: {e}"


market_service = MarketService()


def get_market_data(ticker: str) -> str:
    """
    Fetches comprehensive market data for a given ticker using yfinance.
    Includes historical price data and recent news.

    NOTE: This is a temporary wrapper pending full yfinance integration.
    For AlphaVantage sentiment, use market_service.get_sentiment().
    """
    import yfinance as yf

    logger.info(f"Fetching market data for {ticker} via yfinance")
    report = [f"# Market Data Report for {ticker}"]

    try:
        # 1. Fetch Historical Price
        stock = yf.Ticker(ticker)
        hist = stock.history(period="1mo")

        if not hist.empty:
            report.append("## Recent Price History (Last 1 Month)")
            # Format nicely
            report.append(hist[["Close", "Volume"]].to_markdown())

            latest_close = hist.iloc[-1]["Close"]
            report.append(f"\n**Latest Close:** {latest_close:.2f}")
        else:
            report.append("No price data available.")

    except Exception as e:
        logger.error(f"Error fetching price for {ticker}: {e}")
        report.append(f"Error fetching price: {e}")

    try:
        # 2. Fetch Company News
        news = stock.news
        if news:
            report.append("\n## Recent News")
            # Show top 3
            for item in news[:3]:
                content = item.get("content", item)
                title = content.get("title", "No Title")
                provider = content.get("provider", {})
                publisher = (
                    provider.get("displayName", "Unknown")
                    if isinstance(provider, dict)
                    else provider
                )
                link_obj = content.get("clickThroughUrl", content.get("link", ""))
                link = (
                    link_obj.get("url", "") if isinstance(link_obj, dict) else link_obj
                )
                report.append(f"- **{title}** ({publisher}) [Link]({link})")
        else:
            report.append("\nNo recent news found.")

    except Exception as e:
        logger.error(f"Error fetching news for {ticker}: {e}")
        report.append(f"\nError fetching news: {e}")

    return "\n".join(report)


def get_current_price(symbol: str) -> float | None:
    """
    Synchronous helper to fetch current market price for a symbol.

    Returns the current price as a float, or None if unavailable.
    Used by safety_node.py for deterministic amount computation.
    """
    if not market_service.api_key:
        logger.debug(f"get_current_price({symbol}): ALPHAVANTAGE_API_KEY not set")
        return None

    try:
        params = {
            "function": "GLOBAL_QUOTE",
            "symbol": symbol,
            "apikey": market_service.api_key,
        }

        with httpx.Client() as client:
            response = client.get(market_service.base_url, params=params, timeout=5.0)
            data = response.json()

        # Handle rate limits or errors
        if "Note" in data or "Error Message" in data:
            logger.debug(f"get_current_price({symbol}): API limit or error")
            return None

        quote = data.get("Global Quote", {})
        if not quote:
            logger.debug(f"get_current_price({symbol}): No quote data")
            return None

        price_str = quote.get("05. price")
        if price_str:
            return float(price_str)

        return None

    except Exception as e:
        logger.debug(f"get_current_price({symbol}): Exception {e}")
        return None
