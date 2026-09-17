(() => {
  document.querySelectorAll('form[data-bulk-select]').forEach(form => {
    const selector = form.dataset.bulkSelect || 'input[name="pk"]';
    const rows = [...form.querySelectorAll(selector)].filter(input => !input.disabled);
    const all = form.querySelector('input[name="_all"]');
    const status = form.querySelector('[data-selection-count]');
    if (!status) return;
    const update = () => {
      const count = rows.filter(input => input.checked).length;
      status.textContent = all?.checked ? 'All matching objects selected' : `${count} selected`;
      form.querySelectorAll('[data-select-all]').forEach(button => { button.disabled = !rows.length; });
      form.querySelectorAll('[data-select-none]').forEach(button => { button.disabled = !count && !all?.checked; });
    };
    form.querySelector('[data-select-all]').addEventListener('click', () => {
      rows.forEach(input => { input.checked = true; });
      update();
    });
    form.querySelector('[data-select-none]').addEventListener('click', () => {
      rows.forEach(input => { input.checked = false; });
      if (all) all.checked = false;
      update();
    });
    rows.forEach(input => input.addEventListener('change', () => {
      if (all) all.checked = false;
      update();
    }));
    all?.addEventListener('change', () => {
      rows.forEach(input => { input.checked = all.checked; });
      update();
    });
    update();
  });
})();
