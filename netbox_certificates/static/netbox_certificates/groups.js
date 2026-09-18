(() => {
  document.querySelectorAll(".group-row a, .group-row input").forEach(control => control.addEventListener("click", event => event.stopPropagation()));
  const folders = document.querySelectorAll('details[data-group-id]');
  const searching = Boolean((new URLSearchParams(location.search).get('q') || '').trim());
  folders.forEach(folder => {
    const key = 'nbcert-group-' + folder.dataset.groupId;
    try { if (!searching && localStorage.getItem(key) === 'closed') folder.open = false; } catch (_) {}
    folder.addEventListener('toggle', () => {
      if (searching) return;
      try { localStorage.setItem(key, folder.open ? 'open' : 'closed'); } catch (_) {}
    });
  });
  document.querySelectorAll('[data-expand-all]').forEach(button => {
    button.addEventListener('click', () => folders.forEach(folder => { folder.open = button.dataset.expandAll === 'true'; }));
  });
})();
