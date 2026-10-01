(() => {
  let balance = 500;

  const balanceEl = document.getElementById("balance");
  const statusEl = document.getElementById("status");
  const addMoneyBtn = document.getElementById("addMoney");
  const buyYesBtn = document.getElementById("buyYes");

  function renderBalance() {
    balanceEl.textContent = `$${balance.toFixed(2)}`;
  }

  addMoneyBtn.addEventListener("click", () => {
    balance += 10;
    renderBalance();
  });

  buyYesBtn.addEventListener("click", () => {
    const cost = 6.40;
    if (balance < cost) {
      statusEl.textContent = "Insufficient virtual balance.";
      statusEl.className = "status error";
      return;
    }
    balance -= cost;
    renderBalance();
  });

  fetch("/api/health")
    .then((response) => {
      if (!response.ok) throw new Error("Backend returned an error");
      return response.json();
    })
    .then((data) => {
      statusEl.textContent = `Backend connected ✓ — ${data.status || "ok"}`;
      statusEl.className = "status ok";
    })
    .catch(() => {
      statusEl.textContent = "Backend connection failed.";
      statusEl.className = "status error";
    });

  renderBalance();
})();
