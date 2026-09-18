(() => {
  const initialize = () => {
    const storage = document.getElementById('id_sans');
    const editor = document.getElementById('san-editor');
    if (!storage || !editor || editor.dataset.initialized) return;
    editor.dataset.initialized = 'true';
    const examples = {DNS: 'www.example.com', IP: '192.0.2.10', EMAIL: 'admin@example.com', URI: 'spiffe://example/service'};
    let nextId = 0;

    function synchronize() {
      const entries = [...editor.querySelectorAll('.san-row')].map(row => {
        const value = row.querySelector('.san-value').value.trim();
        return value ? `${row.querySelector('.san-type').value}:${value}` : '';
      }).filter(Boolean);
      storage.value = entries.join('\n');
      document.getElementById('san-count').textContent = `${entries.length} SAN${entries.length === 1 ? '' : 's'}`;
    }

    function addRow(type = 'DNS', value = '', focus = false) {
      const row = document.createElement('div');
      const id = `san-${nextId++}`;
      row.className = 'san-row';
      row.innerHTML = `<div class="san-type-field"><label class="form-label" for="${id}-type">Type</label>
        <select id="${id}-type" class="form-select san-type">
          <option>DNS</option><option>IP</option><option>EMAIL</option><option>URI</option>
        </select></div>
        <div><label class="form-label" for="${id}-value">Value</label>
          <input id="${id}-value" class="form-control san-value" type="text" autocomplete="off" spellcheck="false"></div>
        <button type="button" class="btn btn-outline-secondary san-remove" aria-label="Remove SAN">Remove</button>`;
      const select = row.querySelector('.san-type');
      const input = row.querySelector('.san-value');
      select.value = Object.hasOwn(examples, type) ? type : 'DNS';
      input.value = value;
      input.placeholder = examples[select.value];
      select.addEventListener('change', () => { input.placeholder = examples[select.value]; synchronize(); });
      input.addEventListener('input', synchronize);
      row.querySelector('.san-remove').addEventListener('click', () => {
        row.remove();
        synchronize();
        document.getElementById('add-san').focus();
      });
      editor.appendChild(row);
      if (focus) input.focus();
    }

    const saved = storage.value;
    saved.split(/\r?\n/).map(entry => entry.trim()).filter(Boolean).forEach(entry => {
      const separator = entry.indexOf(':');
      const prefix = entry.slice(0, separator).toUpperCase();
      // Match the server's case-insensitive prefixes and preserve invalid
      // entries in full so redisplaying a validation error cannot lose data.
      const typed = separator > 0 && Object.hasOwn(examples, prefix);
      addRow(typed ? prefix : 'DNS', typed ? entry.slice(separator + 1).trim() : entry);
    });
    if (!editor.children.length) addRow();
    document.getElementById('san-fallback').hidden = true;
    editor.hidden = false;
    const add = document.getElementById('add-san');
    add.hidden = false;
    add.addEventListener('click', () => addRow('DNS', '', true));
    storage.closest('form').addEventListener('submit', synchronize, true);
    synchronize();

    const algorithm = document.getElementById('id_key_algorithm');
    const existingKey = document.getElementById('id_existing_private_key');
    function updateAlgorithm() {
      const existing = Boolean(existingKey.value);
      const value = algorithm.value;
      document.getElementById('key-algorithm-row').hidden = existing;
      document.getElementById('rsa-bits-row').hidden = existing || value !== 'rsa';
      document.getElementById('ec-curve-row').hidden = existing || value !== 'ec';
      document.getElementById('rsa-signature-row').hidden = !existing && value !== 'rsa';
      document.getElementById('signature-hash-row').hidden = !existing && !['rsa', 'ec'].includes(value);
    }
    algorithm.addEventListener('change', updateAlgorithm);
    existingKey.addEventListener('change', updateAlgorithm);
    updateAlgorithm();
    const requestCA = document.getElementById('id_request_ca');
    function updateCA() {
      document.getElementById('path-length-row').hidden = !requestCA.checked;
      document.getElementById('id_path_length').disabled = !requestCA.checked;
    }
    requestCA.addEventListener('change', updateCA);
    updateCA();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize);
  else initialize();
})();
