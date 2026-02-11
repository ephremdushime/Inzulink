// assets/navbar.js
(function () {
  const userRaw = localStorage.getItem("user");
  let user = null;
  try { user = userRaw ? JSON.parse(userRaw) : null; } catch (_) {}

  const current = (location.pathname.split("/").pop() || "index.html").toLowerCase();

  // Decide role-based dashboard link
  let dashLink = "login.html";
  let dashLabel = "Dashboard";
  if (user?.role === "Landlord") { dashLink = "landlord.html"; dashLabel = "Landlord Panel"; }
  if (user?.role === "Admin") { dashLink = "dashboard.html"; dashLabel = "Admin Panel"; }
  if (user?.role === "Seeker") { dashLink = "seeker.html"; dashLabel = "My Wishlist"; }

  // Role badge class
  const roleClass =
    user?.role === "Landlord" ? "role-landlord" :
    user?.role === "Admin" ? "role-admin" :
    user?.role === "Seeker" ? "role-seeker" : "";

  // Primary CTA changes for seeker
  let primaryCtaHref = "post-property.html";
  let primaryCtaText = "List a Property";
  let primaryCtaIcon = "ph-plus-circle";
  if (user?.role === "Seeker") {
    primaryCtaText = "Find a Roommate";
    primaryCtaIcon = "ph-users";
  }
  if (!user) {
    primaryCtaHref = "login.html"; // force login for posting
  }

  // Links (keep them simple + consistent across pages)
  const links = [
    { href: "index.html", label: "Home", icon: "ph-house" },
    { href: "feed.html", label: "Listings", icon: "ph-globe" },
    { href: "contract.html", label: "Contract Tool", icon: "ph-file-text" },
    { href: "careers.html", label: "Careers", icon: "ph-briefcase" },
  ];

  const navHtml = `
    <nav class="app-navbar">
      <a class="app-brand" href="index.html" aria-label="InzuLink Home">
        <span class="brand-icon"><i class="ph ph-house-line"></i></span>
        Inzu<span>Link</span>
      </a>

      <button class="nav-toggle" aria-label="Open menu" aria-expanded="false">
        <i class="ph ph-list"></i>
      </button>

      <div class="app-navlinks">
        ${links.map(l => `
          <a class="app-navlink ${current === l.href.toLowerCase() ? "active" : ""}" href="${l.href}">
            <i class="ph ${l.icon}"></i> ${l.label}
          </a>
        `).join("")}
        <a class="app-navlink cta" href="${primaryCtaHref}">
          <i class="ph ${primaryCtaIcon}"></i> ${primaryCtaText}
        </a>
      </div>

      <div class="app-auth">
        ${
          user ? `
            <div class="user-chip">
              <span class="role-badge ${roleClass}">${user.role}</span>
              <span class="user-name">${(user.name || "User").split(" ")[0]}</span>
              <a class="btn-primary" href="${dashLink}">${dashLabel}</a>
              <button class="btn-ghost" type="button" title="Logout" id="btnLogout">
                <i class="ph ph-sign-out"></i>
              </button>
            </div>
          ` : `
            <a class="btn-ghost" href="login.html">Log In</a>
            <a class="btn-primary" href="signup.html">Sign Up</a>
          `
        }
      </div>
    </nav>
  `;

  // Inject navbar into placeholder
  const mount = document.getElementById("appNavbar");
  if (!mount) return;
  mount.innerHTML = navHtml;

  // Mobile toggle
  const nav = mount.querySelector(".app-navbar");
  const toggle = mount.querySelector(".nav-toggle");
  const linksBox = mount.querySelector(".app-navlinks");
  if (toggle && linksBox) {
    toggle.addEventListener("click", () => {
      const open = linksBox.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // Logout
  const btnLogout = mount.querySelector("#btnLogout");
  if (btnLogout) {
    btnLogout.addEventListener("click", () => {
      localStorage.removeItem("user");
      location.href = "index.html";
    });
  }
})();
