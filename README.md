# Ossper Markets v0.9

Stable core + market engine + emergency controls. Virtual money only.

## v0.9
- Defensive frontend data handling so one malformed market cannot crash the entire interface
- Global admin FREEZE ALL control enforced on the backend
- Freeze/unfreeze events recorded in the audit log
- PostgreSQL ledger entries for balance-changing trades and settlements
- Server-authoritative balances and transactional trade accounting
- Configurable opening probability and market depth/liquidity
- Price impact based on trade notional relative to market liquidity
- Three-decimal contract prices and visible price movement
- Markets / Tournaments / Activity / Portfolio / Settings navigation

## Emergency freeze
When frozen, public trading and quotes are rejected server-side. Automated expiry updates and admin market mutations are paused. Admins can still view the system state, audit trail, and unfreeze the system.

## Important
This remains a virtual-money development environment. It is **not** a real-money trading platform and is not ready for real-money use.
