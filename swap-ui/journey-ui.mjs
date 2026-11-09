import {OFFER_ASSETS, assetInfo, parseOfferLink, toBaseUnits, validateAssetId} from './offer-draft.mjs';
import {validateTerms} from './swap-flow.mjs';

const STEPS = [
  ['give-asset', 'What will you offer?', 'Choose the asset you want to give.'],
  ['give-amount', 'How much will you offer?', 'Enter the amount you are willing to give.'],
  ['receive-asset', 'What would you like in return?', 'Choose the asset you want to receive.'],
  ['receive-amount', 'How much would you like?', 'Enter the amount you want to receive.'],
  ['visibility', 'Who should see your offer?', 'You can share a private link or list it publicly.'],
  ['lifetime', 'How long should it be available?', 'Choose when this offer should expire.'],
  ['backup', 'Protect your inbox key.', 'Choose whether to create an encrypted backup now.'],
  ['review', 'Review your offer.', 'Check the assets, exact amounts and sharing settings before creating it.'],
];

const CONTEXT = {
  browse: ['FIND AN OFFER', 'Explore public offers.', 'Choose an offer to review its exact terms. Reserving an offer does not lock funds.'],
  offer: ['OFFER DETAILS', 'Review this offer.', 'Check what the offer maker gives and receives. You can inspect their identity before reserving.'],
  identity: ['IDENTITY', 'Confirm who you are swapping with.', 'Compare identity codes through a separate trusted channel. Hegemon addresses cannot yet be signed here.'],
  chat: ['MESSAGES', 'Agree on the details.', 'Use the encrypted conversation to coordinate. Never send wallet keys or swap secrets in a message.'],
  guided: ['CONTINUE A SWAP', 'Review an existing native-asset swap.', 'You will need its agreed terms and the status from the local swap engine. This review does not yet support token or NFT swaps, and it does not advance the engine.'],
  wallets: ['WALLETS', 'Connect a wallet.', 'Choose the wallet you need. Connecting does not approve or sign a transaction.'],
  checks: ['VERIFY AN ESCROW', 'Which chain would you like to check?', 'A single-chain check does not establish that the other side is funded or that the swap is safe.'],
  tool: ['WALLET ACTION', 'Review the next action.', 'Check every field and the other swap leg before asking a wallet to sign.'],
};

/** Navigate the existing page without changing any wallet, identity or transaction checks. */
export function initJourney({legacyForm, msg}) {
  const $ = id => document.getElementById(id);
  const shell = $('journey-shell'), form = $('journey-create-form');
  const panels = ['journey-home', 'journey-create', 'journey-created', 'journey-open', 'journey-context'];
  const sections = [...document.querySelectorAll('main > section')].filter(element => element !== shell);
  const hosted = document.documentElement.hasAttribute('data-hosted-testnet');
  const modeKey = 'hegemon.swap.interface-mode.v1';
  let savedMode;
  try { savedMode = sessionStorage.getItem(modeKey); } catch { /* Storage is optional. */ }
  let mode = ['guided', 'advanced'].includes(savedMode) ? savedMode : hosted ? 'guided' : 'advanced';
  let route = 'home', history = [], step = 0, guidedStep = 'terms', posting = false, completedDraft = false, selected = null;

  for (const side of ['give', 'receive']) {
    const select = $(`journey-${side}-type`);
    for (const asset of OFFER_ASSETS) select.add(new Option(asset.label, asset.value));
  }

  function status(id, text, error = false) { msg($(id), text, error); }
  function focusHeading(id) { $(id)?.focus({preventScroll: true}); }
  function byTitle(id) { return document.querySelector(`main > section[aria-labelledby="${id}"]`); }
  function activate(element) { if (element) element.dataset.journeyActive = ''; }
  function contextButton(label, action, secondary = false) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = label;
    if (secondary) button.className = 'journey-secondary';
    button.addEventListener('click', action);
    $('journey-context-actions').append(button);
  }

  function resetDraft() {
    form.reset();
    step = 0;
    completedDraft = false;
    $('journey-backup-fields').hidden = true;
    for (const side of ['give', 'receive']) {
      $(`journey-${side}-id-row`).hidden = true;
      $(`journey-${side}-amount`).readOnly = false;
      $(`journey-${side}-base`).textContent = '';
    }
    status('journey-create-status', '');
  }

  function currentChoice(name) { return form.querySelector(`input[name="${name}"]:checked`)?.value ?? ''; }
  function panelFor(routeName) {
    if (routeName === 'browse') return byTitle('board-title');
    if (routeName === 'offer') return $('selected');
    if (routeName === 'identity') return $('identity');
    if (routeName === 'chat') return $('chat');
    if (routeName === 'guided') return $('guided-section');
    if (routeName === 'wallets') return byTitle('wallet-title');
    if (routeName.startsWith('tool:')) return $(routeName.slice(5));
    return null;
  }

  function render() {
    document.documentElement.dataset.journeyMode = mode;
    shell.hidden = false;
    for (const section of sections) delete section.dataset.journeyActive;
    for (const id of panels) $(id).hidden = true;
    $('journey-offer-next').hidden = true;
    $('journey-progress').textContent = '';
    $('journey-back').hidden = mode !== 'guided' || route === 'home';
    $('journey-mode').disabled = posting;
    $('journey-guided-next').hidden = mode !== 'guided';
    $('journey-guided-previous').hidden = mode !== 'guided';
    $('journey-mode').textContent = mode === 'guided' ? 'Advanced tools' : 'Use guided view';
    if (mode !== 'guided') return;

    const visible = route === 'home' ? 'journey-home' : route === 'create' ? 'journey-create'
      : route === 'created' ? 'journey-created' : route === 'open' ? 'journey-open' : 'journey-context';
    $(visible).hidden = false;
    if (route === 'create') { renderStep(); return; }
    if (route === 'created') {
      $('journey-back').disabled = !$('journey-share-backup').hidden && !$('journey-backup-saved').checked;
      return;
    }
    $('journey-back').disabled = false;
    if (route === 'home' || route === 'open') return;

    const info = CONTEXT[route.startsWith('tool:') ? 'tool' : route];
    if (!info) throw Error('Unknown guided screen.');
    $('journey-context-kicker').textContent = info[0];
    $('journey-context-title').textContent = info[1];
    $('journey-context-copy').textContent = info[2];
    $('journey-context-actions').replaceChildren();
    const panel = panelFor(route);
    if (route === 'guided' && panel) { panel.hidden = false; panel.dataset.journeyGuidedStep = guidedStep; }
    activate(panel);

    if (route === 'offer') {
      const next = $('journey-offer-next');
      next.hidden = !selected?.available;
      $('journey-identity-next').textContent = selected?.participant ? 'Next: confirm identities →' : 'Check the maker’s identity →';
      next.querySelector('p').textContent = selected?.participant
        ? 'Before moving funds, agree on the addresses and confirm the other person’s identity using a separate channel.'
        : 'Check the maker’s identity code through a separate trusted channel before relying on their addresses.';
      if (selected?.owner) contextButton('Share offer link', shareExisting, true);
    }
    if (route === 'identity') {
      contextButton('Connect wallets', () => navigate('wallets'), true);
      if (selected?.participant) contextButton('Continue to messages →', () => navigate('chat'));
    }
    if (route === 'chat') {
      contextButton('Check an escrow', () => navigate('checks'), true);
      contextButton('Review an in-progress swap →', () => navigate('guided'));
    }
    if (route === 'checks') {
      for (const [label, id] of [['Ethereum escrow', 'sepolia-section'], ['Bitcoin escrow', 'bitcoin-testnet-section'], ['Cardano escrow', 'cardano-preview-section']]) {
        contextButton(label, () => navigate('tool:' + id), true);
      }
      const note = document.createElement('p');
      note.className = 'journey-hint';
      note.textContent = 'For Hegemon public-testnet checks, use the local companion with a local copy of the interface. This hosted page cannot connect to your node.';
      $('journey-context-actions').append(note);
    }
    if (route.startsWith('tool:')) contextButton('Return to swap review', () => navigate('guided'), true);
  }

  function navigate(next, remember = true) {
    if (next === 'create' && completedDraft) resetDraft();
    if (remember && next !== route) history.push(route);
    route = next;
    render();
    if (route === 'create') focusHeading('journey-create-title');
    else if (!['home', 'created', 'open'].includes(route)) focusHeading('journey-context-title');
    window.scrollTo({top: 0, behavior: 'instant'});
  }

  function renderStep() {
    const [name, title, description] = STEPS[step];
    for (const element of form.querySelectorAll('[data-journey-step]')) element.hidden = element.dataset.journeyStep !== name;
    $('journey-create-title').textContent = title;
    $('journey-create-description').textContent = description;
    $('journey-progress').textContent = `Step ${step + 1} of ${STEPS.length}`;
    $('journey-create-progress').value = step + 1;
    $('journey-next').hidden = name === 'review';
    $('journey-publish').hidden = name !== 'review';
    $('journey-back').disabled = posting;
    if (name.endsWith('-amount')) updateAmount(name.split('-')[0]);
    if (name === 'review') renderReview();
  }

  function idHelp(side) {
    const value = $(`journey-${side}-type`).value, row = $(`journey-${side}-id-row`);
    const kind = value.split(':')[1], token = ['erc20', 'erc721', 'erc1155', 'native'].includes(kind);
    row.hidden = !token;
    if (!token) return;
    const label = $(`journey-${side}-id-label`), help = $(`journey-${side}-id-help`);
    if (kind === 'erc20') {
      label.textContent = 'Token contract address';
      help.textContent = 'Enter the Ethereum contract address starting with 0x. Verify it independently.';
    } else if (kind === 'native') {
      label.textContent = 'Policy ID and asset name';
      help.textContent = 'Enter the hexadecimal policy ID, a dot, and the hexadecimal asset name. Verify both independently.';
    } else {
      label.textContent = 'Contract address and token ID';
      help.textContent = 'Enter the Ethereum contract address, a colon, and the decimal token ID, for example 0x…:42.';
    }
  }

  function updateAmount(side) {
    const value = $(`journey-${side}-type`).value, field = $(`journey-${side}-amount`);
    if (!value) return;
    const asset = assetInfo(value), kind = value.split(':')[1];
    field.readOnly = kind === 'erc721';
    if (field.readOnly) field.value = '1';
    field.inputMode = asset.decimals === null ? 'numeric' : 'decimal';
    $(`journey-${side}-amount-label`).textContent = `Amount in ${asset.unit}`;
    $(`journey-${side}-amount-help`).textContent = kind === 'erc721' ? 'An ERC-721 offer is for exactly one NFT.'
      : asset.decimals === null ? 'Enter whole base units. If this asset uses decimals, use its verified token details to convert first; this site does not guess them.'
        : `Enter up to ${asset.decimals} decimal places. The exact amount in ${asset.base} is shown below.`;
    const output = $(`journey-${side}-base`);
    if (!field.value.trim()) { output.textContent = ''; return; }
    try { output.textContent = `Exact amount: ${toBaseUnits(value, field.value)} ${asset.base}`; }
    catch { output.textContent = ''; }
  }

  for (const side of ['give', 'receive']) {
    $(`journey-${side}-type`).addEventListener('change', () => {
      $(`journey-${side}-id`).value = '';
      $(`journey-${side}-amount`).value = '';
      idHelp(side);
      updateAmount(side);
    });
    $(`journey-${side}-amount`).addEventListener('input', () => updateAmount(side));
  }
  for (const input of form.querySelectorAll('[name="journey-backup"]')) input.addEventListener('change', () => {
    $('journey-backup-fields').hidden = currentChoice('journey-backup') !== 'yes';
  });

  function draftSide(side) {
    const type = $(`journey-${side}-type`).value;
    return {type, id: validateAssetId(type, $(`journey-${side}-id`).value), amount: toBaseUnits(type, $(`journey-${side}-amount`).value)};
  }
  function validateStep() {
    const name = STEPS[step][0];
    if (name.endsWith('-asset')) {
      const side = name.split('-')[0];
      validateAssetId($(`journey-${side}-type`).value, $(`journey-${side}-id`).value);
    } else if (name.endsWith('-amount')) {
      const side = name.split('-')[0];
      toBaseUnits($(`journey-${side}-type`).value, $(`journey-${side}-amount`).value);
    } else if (name === 'visibility' && !currentChoice('journey-visibility')) throw Error('Choose who can see the offer.');
    else if (name === 'lifetime' && !['3600', '86400', '604000'].includes($('journey-lifetime').value)) throw Error('Choose an offer lifetime.');
    else if (name === 'backup') {
      const choice = currentChoice('journey-backup');
      if (!choice) throw Error('Choose whether to create an inbox backup.');
      if (choice === 'yes') {
        const phrase = $('journey-backup-passphrase').value;
        if (phrase.length < 12 || phrase.length > 1024) throw Error('Use a backup passphrase of 12 to 1024 characters.');
        if (phrase !== $('journey-backup-confirm').value) throw Error('The backup passphrases do not match.');
      }
    }
  }

  function renderReview() {
    const give = draftSide('give'), receive = draftSide('receive');
    const pairs = [];
    for (const [label, side, item] of [['You give', 'give', give], ['You receive', 'receive', receive]]) {
      const asset = assetInfo(item.type), display = $(`journey-${side}-amount`).value.trim();
      pairs.push([label, `${display} ${asset.unit} · ${asset.label}`]);
      pairs.push(['Exact base units', `${item.amount} ${asset.base}`]);
      if (item.id) pairs.push(['Asset identifier', item.id]);
    }
    pairs.push(['Visibility', currentChoice('journey-visibility') === 'public' ? 'Public board' : 'Only people with the link']);
    pairs.push(['Offer lifetime', {'3600': '1 hour', '86400': '1 day', '604000': 'About 7 days'}[$('journey-lifetime').value]]);
    pairs.push(['Inbox key backup', currentChoice('journey-backup') === 'yes' ? 'Encrypted backup' : 'No backup']);
    const list = $('journey-review');
    list.replaceChildren();
    for (const [label, value] of pairs) {
      const dt = document.createElement('dt'), dd = document.createElement('dd');
      dt.textContent = label; dd.textContent = value; list.append(dt, dd);
    }
  }

  function nextStep() {
    if (posting || step === STEPS.length - 1) return;
    try {
      validateStep();
      status('journey-create-status', '');
      step++;
      renderStep();
      focusHeading('journey-create-title');
    } catch (error) { status('journey-create-status', error.message, true); }
  }

  form.addEventListener('submit', event => { event.preventDefault(); nextStep(); });
  $('journey-publish').addEventListener('click', () => {
    if (posting || step !== STEPS.length - 1) return;
    try {
      const give = draftSide('give'), receive = draftSide('receive');
      for (const [side, item] of [['give', give], ['receive', receive]]) {
        legacyForm.elements[side + '-type'].value = item.type;
        legacyForm.elements[side + '-id'].value = item.id;
        legacyForm.elements[side + '-amount'].value = item.amount;
      }
      legacyForm.elements.visibility.value = currentChoice('journey-visibility');
      legacyForm.elements.lifetime.value = $('journey-lifetime').value;
      legacyForm.elements['backup-passphrase'].value = currentChoice('journey-backup') === 'yes' ? $('journey-backup-passphrase').value : '';
      if (!legacyForm.checkValidity()) throw Error('An offer field is incomplete. Go back and check your choices.');
      posting = true;
      $('journey-publish').disabled = true;
      $('journey-back').disabled = true;
      $('journey-mode').disabled = true;
      status('journey-create-status', 'Creating your offer…');
      legacyForm.requestSubmit();
    } catch (error) { posting = false; $('journey-publish').disabled = false; $('journey-back').disabled = false; $('journey-mode').disabled = false; status('journey-create-status', error.message, true); }
  });

  legacyForm.addEventListener('journey:created', () => {
    if (!posting) return;
    posting = false;
    completedDraft = true;
    $('journey-publish').disabled = false;
    $('journey-mode').disabled = false;
    $('journey-backup-passphrase').value = '';
    $('journey-backup-confirm').value = '';
    legacyForm.elements['backup-passphrase'].value = '';
    $('journey-share-link').value = $('share-link').value;
    const hasBackup = !$('inbox-backup').hidden;
    $('journey-share-backup').hidden = !hasBackup;
    $('journey-backup-text').value = hasBackup ? $('inbox-backup-text').value : '';
    $('journey-backup-saved').checked = false;
    $('journey-see-offer').disabled = hasBackup;
    status('journey-share-status', '');
    history = ['home'];
    navigate('created', false);
  });
  legacyForm.addEventListener('journey:failed', event => {
    if (!posting) return;
    posting = false;
    $('journey-publish').disabled = false;
    $('journey-back').disabled = false;
    $('journey-mode').disabled = false;
    status('journey-create-status', `${event.detail?.message || 'Could not create the offer.'} If the response was lost, a public offer may appear on the board; a private offer may be unrecoverable. No funds were locked.`, true);
  });

  $('journey-backup-saved').addEventListener('change', () => {
    const saved = $('journey-backup-saved').checked;
    $('journey-see-offer').disabled = !saved;
    $('journey-back').disabled = !saved;
  });
  async function copy(input, message) {
    try { await navigator.clipboard.writeText(input.value); status('journey-share-status', message); }
    catch { input.focus(); input.select(); status('journey-share-status', 'Select and copy the text above.'); }
  }
  $('journey-copy-link').addEventListener('click', () => copy($('journey-share-link'), 'Offer link copied.'));
  $('journey-copy-backup').addEventListener('click', () => copy($('journey-backup-text'), 'Encrypted backup copied.'));
  $('journey-see-offer').addEventListener('click', () => navigate('offer'));

  $('journey-guided-next').addEventListener('click', () => {
    try {
      validateTerms(JSON.parse($('guided-terms').value));
      guidedStep = 'status';
      status('journey-guided-terms-status', '');
      render();
      $('guided-swap-status').focus();
    } catch (error) { status('journey-guided-terms-status', error instanceof SyntaxError ? 'Enter valid swap terms JSON.' : error.message, true); }
  });
  $('journey-guided-previous').addEventListener('click', () => {
    guidedStep = 'terms';
    render();
    $('guided-terms').focus();
  });

  function shareExisting() {
    const id = selected?.id, key = id && localStorage.getItem('offer-message-key:' + id);
    if (!id || !/^[0-9a-f]{64}$/.test(key || '')) {
      status('detail-status', 'The share link is unavailable in this browser. Use the link you saved when the offer was created.', true);
      return;
    }
    $('journey-share-link').value = location.origin + '/#' + id + '.' + key;
    $('journey-share-backup').hidden = true;
    $('journey-see-offer').disabled = false;
    status('journey-share-status', '');
    navigate('created');
  }

  $('journey-open-form').addEventListener('submit', event => {
    event.preventDefault();
    try {
      const fragment = parseOfferLink($('journey-open-link').value, location.origin);
      status('journey-open-status', 'Opening offer…');
      if (location.hash === fragment) window.dispatchEvent(new Event('hashchange'));
      else location.hash = fragment;
    } catch (error) { status('journey-open-status', error.message, true); }
  });

  document.addEventListener('journey:offer-selected', event => {
    selected = event.detail;
    $('selected').dataset.journeyOwner = String(!!selected.owner);
    $('selected').dataset.journeyReserved = String(!!selected.reserved);
    // A slow offer refresh must not pull a person away from an identity, wallet or swap-review screen.
    if (mode === 'guided' && ['home', 'open', 'browse', 'offer'].includes(route)) navigate('offer', route !== 'offer');
  });
  document.addEventListener('journey:reserved', event => {
    if (selected?.id !== event.detail.id) return;
    selected = {...selected, participant: true, reserved: true};
    $('selected').dataset.journeyReserved = 'true';
    if (mode === 'guided' && route === 'offer') render();
  });
  $('journey-identity-next').addEventListener('click', () => navigate('identity'));
  for (const button of document.querySelectorAll('[data-journey-go]')) button.addEventListener('click', () => navigate(button.dataset.journeyGo));
  $('journey-back').addEventListener('click', () => {
    if (posting) return;
    if (route === 'create' && step > 0) { step--; status('journey-create-status', ''); renderStep(); focusHeading('journey-create-title'); return; }
    route = history.pop() || 'home';
    render();
    window.scrollTo({top: 0, behavior: 'instant'});
  });
  $('journey-mode').addEventListener('click', () => {
    mode = mode === 'guided' ? 'advanced' : 'guided';
    try { sessionStorage.setItem(modeKey, mode); } catch { /* The view still works without storage. */ }
    render();
    window.scrollTo({top: 0, behavior: 'instant'});
  });
  render();
  return {showSection(id) { if (mode === 'guided') navigate('tool:' + id); }};
}
