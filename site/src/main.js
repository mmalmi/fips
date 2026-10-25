const controls = document.querySelector('.mode-controls');
if (controls) {
  const modes = {
    free: {
      title: 'A little bandwidth, freely shared.',
      description: 'When every relay on this route charges zero, traffic can flow without opening payment channels.',
      label: 'Forwarding fee on this example route',
      amount: '0 sats'
    },
    paid: {
      title: 'One route. Each neighbor gets paid.',
      description: 'Relay A adds its 1 sat/MiB fee to B’s 2 sat/MiB quote. The sender pays A; A pays B through a separate channel. Payments accumulate across packets.',
      label: 'Illustrative price for billable traffic',
      amount: '3 sats / MiB'
    }
  };
  controls.hidden = false;
  controls.addEventListener('click', event => {
    const button = event.target.closest('button[data-mode]');
    if (!button) return;
    const mode = modes[button.dataset.mode];
    for (const other of controls.querySelectorAll('button')) other.setAttribute('aria-pressed', String(other === button));
    document.querySelector('#demo-title').textContent = mode.title;
    document.querySelector('#demo-description').textContent = mode.description;
    document.querySelector('#demo-tally-label').textContent = mode.label;
    document.querySelector('#demo-tally').textContent = mode.amount;
  });
}

for (const button of document.querySelectorAll('[data-copy]')) {
  if (!navigator.clipboard) continue;
  button.hidden = false;
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(document.getElementById(button.dataset.copy).textContent);
      button.textContent = 'Copied';
    } catch {
      button.textContent = 'Select text to copy';
    }
    setTimeout(() => { button.textContent = 'Copy'; }, 2500);
  });
}
