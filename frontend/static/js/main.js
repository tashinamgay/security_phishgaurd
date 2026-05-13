// frontend/static/js/main.js
// Member: Aditi (Frontend & DevOps Lead)

document.addEventListener('DOMContentLoaded', function () {

  // ── Mobile Sidebar Toggle ─────────────────────────────
  const sidebar  = document.querySelector('.sidebar');
  const overlay  = document.querySelector('.sidebar-overlay');
  const hamburger = document.querySelector('.hamburger');

  if (hamburger && sidebar) {
    hamburger.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('open');
    });
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('open');
    });
  }

  // ── Upload Zone Drag & Drop ───────────────────────────
  const zone   = document.getElementById('dropZone');
  const input  = document.getElementById('fileInput');
  const label  = document.getElementById('fileName');

  if (zone && input) {
    zone.addEventListener('click', () => input.click());

    input.addEventListener('change', function () {
      if (this.files.length > 0) {
        label.textContent = '✅ ' + this.files[0].name;
        zone.style.borderColor = 'var(--green)';
      }
    });

    zone.addEventListener('dragover',  e => { e.preventDefault(); zone.style.borderColor = 'var(--pri)'; });
    zone.addEventListener('dragleave', ()  => { zone.style.borderColor = ''; });
    zone.addEventListener('drop', e => {
      e.preventDefault();
      zone.style.borderColor = '';
      const f = e.dataTransfer.files[0];
      if (f) {
        const dt = new DataTransfer();
        dt.items.add(f);
        input.files = dt.files;
        label.textContent = '✅ ' + f.name;
        zone.style.borderColor = 'var(--green)';
      }
    });
  }

  // ── Loading State on Analyse Submit ──────────────────
  const form = document.getElementById('analyseForm');
  const btn  = document.getElementById('submitBtn');
  if (form && btn) {
    form.addEventListener('submit', () => {
      btn.textContent = '⏳ Analysing...';
      btn.disabled    = true;
    });
  }

  // ── Auto-dismiss Toasts ───────────────────────────────
  document.querySelectorAll('.toast').forEach(t => {
    setTimeout(() => { t.style.transition = 'opacity .4s'; t.style.opacity = '0'; }, 5000);
    setTimeout(() => t.remove(), 5500);
  });

  // ── Responsive Table Wrapper ──────────────────────────
  // Wrap tables in scroll div on mobile automatically
  document.querySelectorAll('.tbl').forEach(table => {
    if (!table.parentElement.classList.contains('tbl-scroll')) {
      const wrapper = document.createElement('div');
      wrapper.className = 'tbl-scroll';
      table.parentNode.insertBefore(wrapper, table);
      wrapper.appendChild(table);
    }
  });

});
