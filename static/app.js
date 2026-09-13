document.addEventListener("DOMContentLoaded", () => {
  initCopyButtons();
  initCertSearch();
  initSortableTable();
});

function initCopyButtons() {
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;

      try {
        await navigator.clipboard.writeText(target.textContent);
        flashButton(button, "Kopiert!", "copy-success");
      } catch (err) {
        flashButton(button, "Fehler", "copy-error");
      }
    });
  });
}

function flashButton(button, message, className) {
  const original = button.textContent;
  button.textContent = message;
  button.classList.add(className);
  setTimeout(() => {
    button.textContent = original;
    button.classList.remove(className);
  }, 1500);
}

function initCertSearch() {
  const input = document.getElementById("cert-search");
  const table = document.querySelector(".cert-table");
  if (!input || !table) return;

  const rows = Array.from(table.querySelectorAll("tbody tr"));
  input.addEventListener("input", () => {
    const query = input.value.trim().toLowerCase();
    rows.forEach((row) => {
      const hostname = (row.dataset.hostname || "").toLowerCase();
      row.hidden = query.length > 0 && !hostname.includes(query);
    });
  });
}

function initSortableTable() {
  const table = document.querySelector(".cert-table");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  const headers = table.querySelectorAll("th[data-sort-key]");
  let currentKey = null;
  let currentDir = 1;

  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      const numeric = th.dataset.sortType === "number";
      currentDir = currentKey === key ? -currentDir : 1;
      currentKey = key;

      headers.forEach((h) => h.classList.remove("sort-asc", "sort-desc"));
      th.classList.add(currentDir === 1 ? "sort-asc" : "sort-desc");

      const field = toCamelCase(key);
      const rows = Array.from(tbody.querySelectorAll("tr"));

      rows.sort((a, b) => {
        if (numeric) {
          return (parseFloat(a.dataset[field]) - parseFloat(b.dataset[field])) * currentDir;
        }
        return a.dataset[field].localeCompare(b.dataset[field]) * currentDir;
      });

      rows.forEach((row) => tbody.appendChild(row));
    });
  });
}

function toCamelCase(str) {
  return str.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}
