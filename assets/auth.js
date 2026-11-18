document.addEventListener("click", (event) => {
  const link = event.target.closest("a[data-auth-transition]");
  if (!link || event.defaultPrevented || event.button !== 0 ||
      event.metaKey || event.ctrlKey || event.shiftKey || event.altKey ||
      link.target || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    return;
  }

  event.preventDefault();
  const card = document.querySelector(".auth-card");
  if (!card) {
    window.location.assign(link.href);
    return;
  }

  card.classList.add("is-leaving");
  window.setTimeout(() => window.location.assign(link.href), 240);
});
