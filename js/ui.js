// Small page helpers shared by the three pages. No innerHTML anywhere: text goes in as text.

export const $ = (id) => document.getElementById(id);

/** Show one of the page's screens (elements with class "screen") and hide the rest. */
export function show(id) {
  for (const s of document.querySelectorAll('.screen')) s.hidden = s.id !== id;
  window.scrollTo(0, 0);
}

/** Set an element's text. */
export const say = (id, text) => { $(id).textContent = text; };

/** Make a button copy some text, and say so for a moment. */
export function copyButton(btn, getText) {
  const label = btn.textContent;
  btn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(getText()); btn.textContent = 'Copied'; }
    catch { btn.textContent = 'Could not copy'; }
    setTimeout(() => { btn.textContent = label; }, 1500);
  });
}

/** Fill a list element with one item per line of text. */
export function listOf(id, lines) {
  const ul = $(id);
  ul.replaceChildren(...lines.map((l) => Object.assign(document.createElement('li'), { textContent: l })));
}

/** This portal must never run inside another site's frame. */
export function refuseFrames() {
  if (window.top === window.self) return false;
  document.body.replaceChildren(Object.assign(document.createElement('p'), { textContent: 'This page cannot be used inside another site.' }));
  return true;
}
