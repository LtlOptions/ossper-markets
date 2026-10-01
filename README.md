# Ossper Markets — Anti-Scalping Trading Engine Update

This update keeps the existing server-authoritative virtual-money system and adds:

- Real automated liquidity using an LMSR-style market maker instead of the old linear price-jump demo.
- YES + NO = $1.00 at all times.
- 1.00% trading fee on every executed trade.
- 10-second per-market trade cooldown to discourage rapid churn/bot scalping.
- 500-contract maximum position per side per market.
- Existing buy/sell/P&L accounting preserved.
- Automatic database migration for existing Ossper databases.
- Trade history records the fee.

The key anti-manipulation property is that buying to push a price up and immediately selling back cannot manufacture profit from the price movement. The market maker charges increasing prices as a trader pushes the market and the trader also pays the trading fee.

## Files to upload
Replace these files in the GitHub repository:

- `server.js`
- `app.js`
- `index.html`

Do not replace `package.json` unless the existing repository has a different dependency set.

## Current account state
The update does NOT reset existing virtual balances, positions, or trade history.
