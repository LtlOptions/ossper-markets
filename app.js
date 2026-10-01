(() => {
  const $ = (id) => document.getElementById(id);
  let markets = [];

  function money(value) {
    return `$${Number(value).toFixed(2)}`;
  }

  function toast(message, good = true) {
    const el = $("toast");
    el.textContent = message;
    el.style.display = "block";
    el.style.borderColor = good ? "#355f4a" : "#6b3b3b";
    setTimeout(() => { el.style.display = "none"; }, 2200);
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

    container.innerHTML = markets.map(m => `
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
            <button data-buy="YES" data-market="${m.id}">Buy YES</button>
            ${m.position.yesContracts ? `<div style="margin-top:8px" class="muted">Own ${m.position.yesContracts}</div>` : ""}
          </div>
          <div class="quote no">
            <div class="quote-label">NO</div>
            <div class="price">${money(m.noPrice)}</div>
            <button data-buy="NO" data-market="${m.id}">Buy NO</button>
            ${m.position.noContracts ? `<div style="margin-top:8px" class="muted">Own ${m.position.noContracts}</div>` : ""}
          </div>
        </div>

        <div class="meta">
          <span>Volume ${money(m.volume)}</span>
          <span>YES + NO = $1.00</span>
        </div>
      </article>
    `).join("");

    container.querySelectorAll("[data-buy]").forEach(button => {
      button.addEventListener("click", () => executeTrade(button.dataset.market, button.dataset.buy, "BUY"));
    });
  }

  function renderPositions() {
    const items = [];
    markets.forEach(m => {
      if (m.position.yesContracts) {
        items.push(`<div class="position"><div class="pos-row"><strong>YES</strong><strong>${m.position.yesContracts}</strong></div><div class="muted">${escapeHtml(m.title)}</div><div class="muted">Cost ${money(m.position.yesCost)}</div></div>`);
      }
      if (m.position.noContracts) {
        items.push(`<div class="position"><div class="pos-row"><strong>NO</strong><strong>${m.position.noContracts}</strong></div><div class="muted">${escapeHtml(m.title)}</div><div class="muted">Cost ${money(m.position.noCost)}</div></div>`);
      }
    });
    $("positions").innerHTML = items.length ? items.join("") : "No open positions yet.";
  }

  function renderHistory(trades) {
    $("history").innerHTML = trades.length ? trades.map(t =>
      `<div class="history-item"><strong>${t.action} ${t.contracts} ${t.side}</strong> @ ${money(t.price)}<br><span class="muted">${escapeHtml(t.title)} · ${money(t.total)}</span></div>`
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
      renderHistory(history.trades);
      $("status").textContent = "Ossper engine connected ✓ · server-authoritative virtual balance";
      $("status").className = "ok";
    } catch (error) {
      $("status").textContent = error.message;
      $("status").className = "error";
    }
  }

  async function executeTrade(marketId, side, action) {
    const quantity = Number(prompt(`How many ${side} contracts?`, "1"));
    if (!Number.isInteger(quantity) || quantity < 1) return;

    try {
      const result = await api("/api/trades", {
        method: "POST",
        body: JSON.stringify({ marketId, side, action, contracts: quantity })
      });
      toast(`${action} ${quantity} ${side} executed at ${money(result.trade.price)}`);
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
