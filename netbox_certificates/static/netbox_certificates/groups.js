(() => {
  const folders = document.querySelectorAll('details[data-group-id]');
  const searching = new URLSearchParams(location.search).has('q');
  folders.forEach(folder => {
    const key = 'nbcert-group-' + folder.dataset.groupId;
    try { if (!searching && localStorage.getItem(key) === 'closed') folder.open = false; } catch (_) {}
    folder.addEventListener('toggle', () => {
      try { localStorage.setItem(key, folder.open ? 'open' : 'closed'); } catch (_) {}
    });
  });
  document.querySelectorAll('[data-expand-all]').forEach(button => {
    button.addEventListener('click', () => folders.forEach(folder => { folder.open = button.dataset.expandAll === 'true'; }));
  });
})();
