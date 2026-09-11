(() => {
  const pfx = document.getElementById('id_export_pfx');
  const protect = document.getElementById('id_protect_pfx');
  if (!pfx || !protect) return;
  const update = () => {
    document.getElementById('pfx-options').hidden = !pfx.checked;
    document.getElementById('pfx-passwords').hidden = !protect.checked;
  };
  pfx.addEventListener('change', update);
  protect.addEventListener('change', update);
  update();
})();
