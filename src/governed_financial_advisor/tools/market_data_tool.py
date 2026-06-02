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
import yfinance as yf
import pandas as pd

logger = logging.getLogger(__name__)

def get_market_data(ticker: str) -> str:
    """
    Fetches comprehensive market data for a given ticker using yfinance.
    Includes historical price data and recent news.
    """
    logger.info(f"Fetching market data for {ticker} via yfinance")
    report = [f"# Market Data Report for {ticker}"]

    try:
        # 1. Fetch Historical Price
        stock = yf.Ticker(ticker)
        hist = stock.history(period="1mo")
        
        if not hist.empty:
             report.append("## Recent Price History (Last 1 Month)")
             # Format nicely
             report.append(hist[['Close', 'Volume']].to_markdown())
             
             latest_close = hist.iloc[-1]['Close']
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
                content = item.get('content', item)
                title = content.get('title', 'No Title')
                provider = content.get('provider', {})
                publisher = provider.get('displayName', 'Unknown') if isinstance(provider, dict) else provider
                link_obj = content.get('clickThroughUrl', content.get('link', ''))
                link = link_obj.get('url', '') if isinstance(link_obj, dict) else link_obj
                report.append(f"- **{title}** ({publisher}) [Link]({link})")
        else:
             report.append("\nNo recent news found.")

    except Exception as e:
        logger.error(f"Error fetching news for {ticker}: {e}")
        report.append(f"\nError fetching news: {e}")

    return "\n".join(report)
