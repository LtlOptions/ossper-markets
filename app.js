(() => {
  const $ = (id) => document.getElementById(id);
  let markets = [];

  function money(value) {
    return `$${Number(value).toFixed(2)}`;
  }

  function signedMoney(value) {
    const n = Number(value);
    return `${n >= 0 ? "+" : "-"}$${Math.abs(n).toFixed(2)}`;
  }

  function toast(message, good = true) {
    const el = $("toast");
    el.textContent = message;
    el.style.display = "block";
    el.style.borderColor = good ? "#355f4a" : "#6b3b3b";
    clearTimeout(window.__ossperToast);
    window.__ossperToast = setTimeout(() => { el.style.display = "none"; }, 2400);
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) }
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  function renderMarkets() {
    const container = $("markets");
    if (!markets.length) {
      container.innerHTML = '<div class="muted">No markets are open.</div>';
      return;
    }

    container.innerHTML = markets.map(m => {
      const y = m.position.yesContracts;
      const n = m.position.noContracts;
      return `
      <article class="market">
        <div class="market-top">
          <div class="market-title">${escapeHtml(m.title)}</div>
          <div class="tag">${m.status}</div>
        </div>
        <div class="desc">${escapeHtml(m.description)}</div>

        <div class="prices">
          <div class="quote yes">
            <div class="quote-label">YES</div>
            <div class="price">${money(m.yesPrice)}</div>
            <button data-action="BUY" data-side="YES" data-market="${m.id}">Buy YES</button>
            ${y ? `<button class="sell" data-action="SELL" data-side="YES" data-market="${m.id}">Sell YES</button>` : ""}
            ${y ? `<div class="position-mini">Own ${y} · Avg ${money(m.position.yesAvgPrice)}</div>` : ""}
          </div>
          <div class="quote no">
            <div class="quote-label">NO</div>
            <div class="price">${money(m.noPrice)}</div>
            <button data-action="BUY" data-side="NO" data-market="${m.id}">Buy NO</button>
            ${n ? `<button class="sell" data-action="SELL" data-side="NO" data-market="${m.id}">Sell NO</button>` : ""}
            ${n ? `<div class="position-mini">Own ${n} · Avg ${money(m.position.noAvgPrice)}</div>` : ""}
          </div>
        </div>

        <div class="meta">
          <span>Volume ${money(m.volume)}</span>
          <span>YES + NO = $1.00</span><span>1% fee · 10s cooldown</span>
        </div>
      </article>`;
    }).join("");

    container.querySelectorAll("[data-action]").forEach(button => {
      button.addEventListener("click", () => executeTrade(
        button.dataset.market,
        button.dataset.side,
        button.dataset.action
      ));
    });
  }

  function renderPositions() {
    const items = [];
    markets.forEach(m => {
      const p = m.position;
      if (p.yesContracts) {
        items.push(`
          <div class="position">
            <div class="pos-row"><strong>YES</strong><strong>${p.yesContracts}</strong></div>
            <div class="muted">${escapeHtml(m.title)}</div>
            <div class="position-stats">Avg ${money(p.yesAvgPrice)} · Value ${money(p.yesValue)} · P/L ${signedMoney(p.yesUnrealizedPnl)}</div>
          </div>`);
      }
      if (p.noContracts) {
        items.push(`
          <div class="position">
            <div class="pos-row"><strong>NO</strong><strong>${p.noContracts}</strong></div>
            <div class="muted">${escapeHtml(m.title)}</div>
            <div class="position-stats">Avg ${money(p.noAvgPrice)} · Value ${money(p.noValue)} · P/L ${signedMoney(p.noUnrealizedPnl)}</div>
          </div>`);
      }
    });
    $("positions").innerHTML = items.length ? items.join("") : "No open positions yet.";
  }

  function renderSummary() {
    let realized = 0;
    let unrealized = 0;
    let value = 0;
    markets.forEach(m => {
      realized += Number(m.position.realizedPnl || 0);
      unrealized += Number(m.position.yesUnrealizedPnl || 0) + Number(m.position.noUnrealizedPnl || 0);
      value += Number(m.position.yesValue || 0) + Number(m.position.noValue || 0);
    });
    $("realized").textContent = signedMoney(realized);
    $("unrealized").textContent = signedMoney(unrealized);
    $("positionValue").textContent = money(value);
  }

  function renderHistory(trades) {
    $("history").innerHTML = trades.length ? trades.map(t =>
      `<div class="history-item"><strong>${t.action} ${t.contracts} ${t.side}</strong> @ ${money(t.price)}<br><span class="muted">${escapeHtml(t.title)} · ${money(t.total)} · fee ${money(t.fee || 0)}</span></div>`
    ).join("") : "No trades yet.";
  }

  async function load() {
    try {
      const [me, marketData, history] = await Promise.all([
        api("/api/me"),
        api("/api/markets"),
        api("/api/history")
      ]);
      $("balance").textContent = money(me.balance);
      markets = marketData.markets;
      renderMarkets();
      renderPositions();
      renderSummary();
      renderHistory(history.trades);
      $("status").textContent = "Ossper engine connected ✓ · server-authoritative virtual balance";
      $("status").className = "ok";
    } catch (error) {
      $("status").textContent = error.message;
      $("status").className = "error";
    }
  }

  async function executeTrade(marketId, side, action) {
    const market = markets.find(m => m.id === marketId);
    const owned = market ? Number(side === "YES" ? market.position.yesContracts : market.position.noContracts) : 0;
    const promptText = action === "SELL"
      ? `How many ${side} contracts do you want to sell? You own ${owned}.`
      : `How many ${side} contracts do you want to buy?`;
    const quantity = Number(prompt(promptText, "1"));
    if (!Number.isInteger(quantity) || quantity < 1) return;
    if (action === "SELL" && quantity > owned) {
      toast(`You only own ${owned} ${side} contract${owned === 1 ? "" : "s"}.`, false);
      return;
    }

    try {
      const result = await api("/api/trades", {
        method: "POST",
        body: JSON.stringify({ marketId, side, action, contracts: quantity })
      });
      toast(`${action} ${quantity} ${side} @ ${money(result.trade.price)} · fee ${money(result.fee)}`);
      await load();
    } catch (error) {
      toast(error.message, false);
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({
      "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
    }[char]));
  }

  load();
})();
