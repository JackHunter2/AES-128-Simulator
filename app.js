const dom = {
  heroFormula: document.getElementById('heroFormula'),
  modeButtons: Array.from(document.querySelectorAll('.mode-btn')),
  ptLabel: document.getElementById('ptLabel'),
  ptHint: document.getElementById('ptHint'),
  ptInput: document.getElementById('plaintextInput'),
  ptFormatToggle: document.getElementById('ptFormatToggle'),
  ptError: document.getElementById('ptError'),
  keyInput: document.getElementById('keyInput'),
  keyError: document.getElementById('keyError'),
  randomKeyBtn: document.getElementById('randomKeyBtn'),
  runBtn: document.getElementById('runBtn'),
  runBtnLabel: document.getElementById('runBtnLabel'),
  resetBtn: document.getElementById('resetBtn'),
  traceToggle: document.getElementById('traceToggle'),
  outputBlock: document.getElementById('outputBlock'),
  outputLabel: document.getElementById('outputLabel'),
  outputValue: document.getElementById('outputValue'),
  copyBtn: document.getElementById('copyBtn'),
  keyExpansionPanel: document.getElementById('keyExpansionPanel'),
  keyExpansionBody: document.getElementById('keyExpansionBody'),
  roundsContainer: document.getElementById('roundsContainer'),
  roundList: document.getElementById('roundList'),
};

const state = {
  mode: 'encrypt',
  plaintextFormat: 'text',
  lastOutputHex: '',
  currentResult: null,
};

const FORMULAS = {
  hero: '\\mathbf{S}_{i+1} = T_{\\text{round}}(\\mathbf{S}_i, \\mathbf{RK}_i)',
  subBytes: '\\mathbf{a}\\_j \\leftarrow S[\\mathbf{a}\\_j]',
  invSubBytes: '\\mathbf{a}\\_j \\leftarrow S^{-1}[\\mathbf{a}\\_j]',
  shiftRows: '\\text{Row}_r \\leftarrow \\operatorname{rotl}(\\text{Row}_r, r)',
  invShiftRows: '\\text{Row}_r \\leftarrow \\operatorname{rotr}(\\text{Row}_r, r)',
  mixColumns: '\\mathbf{s}' + "'" + ' = M \\cdot \\mathbf{s}',
  invMixColumns: '\\mathbf{s}' + "'" + ' = M^{-1} \\cdot \\mathbf{s}',
  addRoundKey: '\\mathbf{s}' + "'" + ' = \\mathbf{s} \\oplus \\mathbf{RK}_r',
  initialRound: '\\mathbf{s} \\leftarrow \\mathbf{s} \\oplus \\mathbf{RK}_0',
  keyExpansion: 'W_i = W_{i-4} \\oplus g(W_{i-1}), \\quad g(x)=\\operatorname{SubWord}(\\operatorname{RotWord}(x)) \\oplus \\operatorname{Rcon}_{i/4}',
};

function renderMathElement(element, latex, displayMode = false) {
  if (!element) {
    return;
  }

  if (window.katex && typeof window.katex.render === 'function') {
    element.innerHTML = '';
    try {
      window.katex.render(latex, element, {
        displayMode,
        throwOnError: false,
        strict: false,
      });
      return;
    } catch (error) {
      // fall through to plain text
    }
  }

  element.textContent = latex;
}

function stepFormula(op) {
  return FORMULAS[op] || '';
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function statusLabel(bytes) {
  const text = bytesToHex(bytes);
  const preview = text.slice(0, 8);
  return preview ? preview.toUpperCase() + '…' : '—';
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '').toLowerCase();
  if (clean.length !== 32) {
    throw new Error('Harus 32 karakter hex (16 byte).');
  }
  if (!/^[0-9a-f]{32}$/.test(clean)) {
    throw new Error('Input hex tidak valid.');
  }

  const bytes = new Uint8Array(16);
  for (let index = 0; index < 16; index++) {
    bytes[index] = parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function textToBlock(text) {
  const encoder = new TextEncoder();
  const raw = encoder.encode(text);
  if (raw.length > 16) {
    throw new Error('Teks maksimal 16 byte.');
  }

  const bytes = new Uint8Array(16);
  bytes.set(raw);
  return bytes;
}

function setError(element, message) {
  element.textContent = message || '';
}

function setMode(mode) {
  state.mode = mode;
  for (const button of dom.modeButtons) {
    const active = button.dataset.mode === mode;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-selected', String(active));
  }

  dom.runBtnLabel.textContent = mode === 'encrypt' ? 'ENCRYPT' : 'DECRYPT';
  dom.ptLabel.textContent = mode === 'encrypt' ? 'Plaintext' : 'Ciphertext';
  dom.ptHint.textContent = mode === 'encrypt'
    ? 'Teks (maks. 16 karakter) atau 32 hex'
    : '32 karakter hex (16 byte)';

  if (mode === 'decrypt') {
    setPlaintextFormat('hex');
  }
}

function setPlaintextFormat(format) {
  state.plaintextFormat = format;
  for (const button of dom.ptFormatToggle.querySelectorAll('.fmt-btn')) {
    button.classList.toggle('is-active', button.dataset.fmt === format);
  }
  dom.ptInput.placeholder = format === 'text'
    ? 'mis. attackatdawn12 atau 16 karakter'
    : 'mis. 00112233445566778899aabbccddeeff';
}

function renderMatrix(title, bytes) {
  const template = document.getElementById('matrixTemplate');
  const block = template.content.firstElementChild.cloneNode(true);
  block.querySelector('.matrix-block-label').textContent = title;
  const grid = block.querySelector('.matrix-grid');

  for (let row = 0; row < 4; row++) {
    for (let column = 0; column < 4; column++) {
      const cell = document.createElement('div');
      cell.className = 'byte-cell';
      cell.textContent = bytes[column * 4 + row].toString(16).padStart(2, '0');
      grid.appendChild(cell);
    }
  }

  return block;
}

function renderKeyExpansion(result) {
  dom.keyExpansionBody.innerHTML = '';

  const formula = document.createElement('div');
  formula.className = 'formula-callout';
  const formulaMath = document.createElement('div');
  formulaMath.className = 'formula-callout-math';
  renderMathElement(formulaMath, FORMULAS.keyExpansion, true);
  const formulaCaption = document.createElement('div');
  formulaCaption.className = 'formula-callout-caption';
  formulaCaption.textContent = 'Setiap word baru dibangun dari word sebelumnya dengan RotWord, SubWord, dan Rcon.';
  formula.appendChild(formulaMath);
  formula.appendChild(formulaCaption);
  dom.keyExpansionBody.appendChild(formula);

  const summary = document.createElement('div');
  summary.className = 'key-expansion-summary';
  summary.textContent = 'Total words: ' + result.words.length + ' · Round keys: ' + result.roundKeys.length;
  dom.keyExpansionBody.appendChild(summary);

  const keys = document.createElement('div');
  keys.className = 'key-expansion-list';

  for (let round = 0; round < result.roundKeys.length; round++) {
    const item = document.createElement('div');
    item.className = 'key-expansion-item';

    const label = document.createElement('div');
    label.className = 'key-expansion-label';
    label.textContent = 'RK' + round;

    const value = document.createElement('code');
    value.className = 'mono';
    value.textContent = bytesToHex(result.roundKeys[round]);

    const preview = document.createElement('span');
    preview.className = 'key-expansion-preview';
    preview.textContent = 'round ' + round;

    item.appendChild(label);
    item.appendChild(preview);
    item.appendChild(value);
    keys.appendChild(item);
  }

  dom.keyExpansionBody.appendChild(keys);

  if (result.log.length) {
    const title = document.createElement('h3');
    title.textContent = 'Word g';
    dom.keyExpansionBody.appendChild(title);

    const logList = document.createElement('div');
    logList.className = 'key-expansion-log';

    for (const entry of result.log) {
      const item = document.createElement('div');
      item.className = 'key-expansion-log-item';
      item.textContent = 'W[' + entry.wordIndex + '] · prev=' + bytesToHex(entry.prevWord) + ' · rot=' + bytesToHex(entry.rotWord) + ' · sub=' + bytesToHex(entry.subWord) + ' · rcon=' + bytesToHex(entry.rcon) + ' · xor=' + bytesToHex(entry.xorResult);
      logList.appendChild(item);
    }

    dom.keyExpansionBody.appendChild(logList);
  }

  dom.keyExpansionPanel.hidden = false;
}

function renderRounds(rounds) {
  dom.roundsContainer.innerHTML = '';
  dom.roundList.innerHTML = '';

  for (const round of rounds) {
    const navItem = document.createElement('li');
    navItem.className = round.index === 0 ? 'rn-key' : (round.index === 10 ? 'rn-key' : '');
    const navLink = document.createElement('a');
    navLink.href = '#round-' + round.index;
    navLink.innerHTML = '<span class="rn-tag"></span><span>' + round.label + '</span>';
    navItem.appendChild(navLink);
    dom.roundList.appendChild(navItem);

    const section = document.createElement('section');
    section.className = 'round-card';
    section.id = 'round-' + round.index;

    const head = document.createElement('button');
    head.type = 'button';
    head.className = 'round-card-head';
    head.setAttribute('aria-expanded', 'true');

    const badge = document.createElement('span');
    badge.className = 'round-badge';
    badge.textContent = round.index === 0 ? 'INIT' : (round.index === 10 ? 'FINAL' : 'R' + round.index);

    const title = document.createElement('span');
    title.className = 'round-card-title';
    title.textContent = round.label;

    const sub = document.createElement('span');
    sub.className = 'round-card-sub';
    sub.textContent = round.steps.length + ' steps';

    head.appendChild(badge);
    head.appendChild(title);
    head.appendChild(sub);
    section.appendChild(head);

    const opList = document.createElement('div');
    opList.className = 'op-list';

    const heading = document.createElement('h3');
    heading.hidden = true;
    heading.textContent = round.label;
    section.appendChild(heading);

    for (const step of round.steps) {
      const stepRow = document.createElement('div');
      stepRow.className = 'op-step';

      const stepLabel = document.createElement('div');
      stepLabel.className = 'op-step-head';

      const tag = document.createElement('span');
      tag.className = 'op-tag ' + (step.op.includes('Inv') ? 'op-tag--inv' : (step.op === 'AddRoundKey' ? 'op-tag--key' : (step.op === 'MixColumns' || step.op === 'InvMixColumns' ? 'op-tag--mix' : 'op-tag--sub')));
      tag.textContent = step.op;

      const desc = document.createElement('span');
      desc.className = 'op-desc';
      desc.textContent = typeof step.roundKeyIndex === 'number' ? 'Round key ' + step.roundKeyIndex : 'State transform';

      const formulaRow = document.createElement('div');
      formulaRow.className = 'op-desc math-line';
      renderMathElement(formulaRow, stepFormula(step.op), false);

      const matrices = document.createElement('div');
      matrices.className = 'matrix-pair';
      matrices.appendChild(renderMatrix('Before', step.before));
      const arrow = document.createElement('div');
      arrow.className = 'matrix-arrow';
      arrow.textContent = '→';
      matrices.appendChild(arrow);
      matrices.appendChild(renderMatrix('After', step.after));

      const beforeMatrix = matrices.querySelectorAll('.matrix-grid')[0];
      const afterMatrix = matrices.querySelectorAll('.matrix-grid')[1];
      if (beforeMatrix && afterMatrix) {
        const beforeCells = beforeMatrix.querySelectorAll('.byte-cell');
        const afterCells = afterMatrix.querySelectorAll('.byte-cell');
        for (let i = 0; i < afterCells.length; i++) {
          if (beforeCells[i] && afterCells[i] && beforeCells[i].textContent !== afterCells[i].textContent) {
            afterCells[i].classList.add('is-changed');
          }
        }
      }

      stepLabel.appendChild(tag);
      stepLabel.appendChild(desc);
      stepRow.appendChild(stepLabel);
      stepRow.appendChild(formulaRow);
      stepRow.appendChild(matrices);
      opList.appendChild(stepRow);
    }

    section.appendChild(opList);
    dom.roundsContainer.appendChild(section);
  }

  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) {
      return;
    }

    dom.roundList.querySelectorAll('a').forEach((link) => link.classList.remove('is-current'));
    const activeLink = dom.roundList.querySelector('a[href="#' + visible.target.id + '"]');
    if (activeLink) {
      activeLink.classList.add('is-current');
    }
  }, { threshold: 0.35 });

  dom.roundsContainer.querySelectorAll('.round-card').forEach((card) => {
    observer.observe(card);
    const head = card.querySelector('.round-card-head');
    const body = card.querySelector('.op-list');
    if (!head || !body) {
      return;
    }

    head.addEventListener('click', () => {
      const collapsed = body.hasAttribute('hidden');
      if (collapsed) {
        body.removeAttribute('hidden');
      } else {
        body.setAttribute('hidden', '');
      }
      head.setAttribute('aria-expanded', String(collapsed));
    });
  });
}

function showResult(result, mode) {
  const bytes = mode === 'encrypt' ? result.ciphertext : result.plaintext;
  state.lastOutputHex = bytesToHex(bytes);
  state.currentResult = result;
  dom.outputLabel.textContent = mode === 'encrypt' ? 'Ciphertext (hex)' : 'Plaintext (hex)';
  dom.outputValue.textContent = state.lastOutputHex;
  dom.outputBlock.hidden = false;

  if (dom.heroFormula) {
    renderMathElement(dom.heroFormula, FORMULAS.hero, true);
  }

  renderKeyExpansion(result.keyExpansion);
  if (dom.traceToggle.checked) {
    renderRounds(result.rounds);
  } else {
    dom.roundsContainer.innerHTML = '';
    dom.roundList.innerHTML = '';
  }
}

function runAES() {
  setError(dom.ptError, '');
  setError(dom.keyError, '');

  try {
    const keyBytes = hexToBytes(dom.keyInput.value);
    const inputValue = dom.ptInput.value.trim();

    if (!inputValue) {
      throw new Error('Input tidak boleh kosong.');
    }

    if (state.mode === 'encrypt') {
      const block = state.plaintextFormat === 'hex' ? hexToBytes(inputValue) : textToBlock(inputValue);
      showResult(AES.encryptBlock(block, keyBytes), 'encrypt');
      return;
    }

    showResult(AES.decryptBlock(hexToBytes(inputValue), keyBytes), 'decrypt');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('kunci') || message.includes('hex')) {
      setError(dom.keyError, message);
    } else {
      setError(dom.ptError, message);
    }
    dom.outputBlock.hidden = true;
    dom.keyExpansionPanel.hidden = true;
    dom.roundsContainer.innerHTML = '';
    dom.roundList.innerHTML = '';
  }
}

function resetForm() {
  dom.ptInput.value = '';
  dom.keyInput.value = '';
  setError(dom.ptError, '');
  setError(dom.keyError, '');
  dom.outputBlock.hidden = true;
  dom.keyExpansionPanel.hidden = true;
  dom.keyExpansionBody.innerHTML = '';
  dom.roundsContainer.innerHTML = '';
  dom.roundList.innerHTML = '';
  state.lastOutputHex = '';
}

function randomKey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  dom.keyInput.value = bytesToHex(bytes);
}

dom.modeButtons.forEach((button) => {
  button.addEventListener('click', () => setMode(button.dataset.mode));
});

dom.ptFormatToggle.querySelectorAll('.fmt-btn').forEach((button) => {
  button.addEventListener('click', () => setPlaintextFormat(button.dataset.fmt));
});

dom.runBtn.addEventListener('click', runAES);
dom.resetBtn.addEventListener('click', resetForm);
dom.randomKeyBtn.addEventListener('click', randomKey);
dom.copyBtn.addEventListener('click', async () => {
  if (!state.lastOutputHex) {
    return;
  }
  await navigator.clipboard.writeText(state.lastOutputHex);
});
dom.traceToggle.addEventListener('change', () => {
  if (!dom.outputBlock.hidden && state.currentResult) {
    if (dom.traceToggle.checked) {
      renderRounds(state.currentResult.rounds);
    } else {
      dom.roundsContainer.innerHTML = '';
      dom.roundList.innerHTML = '';
    }
  } else {
    dom.roundsContainer.innerHTML = '';
    dom.roundList.innerHTML = '';
  }
});

setMode('encrypt');
setPlaintextFormat('text');
renderMathElement(dom.heroFormula, FORMULAS.hero, true);