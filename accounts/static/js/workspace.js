/* Navigation only: existing page-specific handlers remain independent. */
(() => {
  const sidebar = document.getElementById('workspace-navigation');
  const toggle = document.getElementById('workspace-toggle');
  if (!sidebar || !toggle) return;
  const mobile = window.matchMedia('(max-width: 900px)');
  function setOpen(open) {
    if (!open && sidebar.contains(document.activeElement)) toggle.focus();
    sidebar.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
  }
  function synchronize() {
    toggle.hidden = !mobile.matches;
    setOpen(!mobile.matches);
  }
  toggle.addEventListener('click', () => setOpen(sidebar.hidden));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && mobile.matches && !sidebar.hidden) {
      setOpen(false);
      toggle.focus();
    }
  });
  mobile.addEventListener('change', synchronize);
  synchronize();
})();
