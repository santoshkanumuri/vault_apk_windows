# Nuvori landing page

A static page: `index.html`, `styles.css`, `script.js` and `palette.js`, plus images in `assets/`. It has no build step and no runtime dependencies. Only the fonts come from Google Fonts.

## Preview locally

```powershell
python -m http.server 8765 --directory landing
```

Then open http://127.0.0.1:8765/.

## Host on GitHub Pages

GitHub Pages can publish only the repository root or a `docs/` folder from a branch. To publish this folder, use one of these options:

1. **A separate repository.** Copy the contents of `landing/` to the root of a new public repository. Then open **Settings > Pages** and choose **Deploy from a branch**, `main`, `/ (root)`.
2. **This repository, through GitHub Actions.** Open **Settings > Pages** and choose **GitHub Actions**. Then add `.github/workflows/pages.yml`:

```yaml
name: Landing page
on:
  push:
    branches: [main]
    paths: [landing/**]
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
concurrency: { group: pages, cancel-in-progress: true }
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: { name: github-pages, url: "${{ steps.deployment.outputs.page_url }}" }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-pages-artifact@v3
        with: { path: landing }
      - id: deployment
        uses: actions/deploy-pages@v4
```

The empty `.nojekyll` file stops GitHub from running Jekyll over the files.

After the first deploy, open the page URL in a private window. Then you can use it as the **Website** in Partner Center.

## Update the content

- **Store links** sit in `index.html`, in the `#download` section, in each card's `href` and `data-copy`.
- **Privacy policy and terms of service** are `privacy/index.html` and `terms/index.html` (shared at `/privacy/` and `/terms/`), styled by `legal.css`. When an app changes what data it handles, update the policy and its effective date in the same release.
- **The tester sign-up form** (Google Form) is the **Join testing** button in the closing call to action (`#join-testing`) and the footer link of the same name. When the apps leave closed testing, remove both and the `.cta__note` line.
- **The "Under review", "Closed testing" and "Available" tags** are the `.tag` elements in the same cards (`.tag--amber`, `.tag--violet`, `.tag--green`). The extension card links to the Chrome Web Store item `lpohaakdindhljdhpofnfmggbfllgdil`, with `assets/qr-chrome-web-store.svg`.
- **QR codes** (`assets/qr-*.svg`) are made from the store URLs. If a URL changes, make the QR code again, and scan it before you publish.
- **`palette.js`** is generated. Run `python scripts/appearance/generate.py <path to card_app_windows>` in the Android repository, and it rewrites this file together with the app palettes.
- **Browser names** (hero, marquee, "Pick a browser" chips, `#browsers` lists, FAQ "Switching browsers") must match what Nuvori for Windows recognizes in `src-tauri/src/browsers.rs` (`classify`). The chips' steps and notes are in `BROWSERS` in `script.js`. Name browsers as text only, never with their logos.
- **Screenshots** in `assets/` are WebP copies of `card_app/docs/assets/screenshots` and `store-assets/`, with synthetic sample data only.

## FAQ page

The FAQ is `faq/index.html`, shared at `/faq/`. `faq/faq.css` styles it with the tokens from `styles.css`. `faq/faq.js` adds search, the topic filter, deep links and the **Copy link** buttons. The script reads the page, so a new question needs no script change. Without JavaScript, every question still shows, and the topic links jump to their section.

### Add a question

1. Open `faq/index.html` and find the section of the topic, for example `<section ... data-faq-category="backup">`.
2. Copy this block into its `<div class="faq__list">`:

```html
<details class="qa" id="short-question-id">
  <summary><span class="qa__q">The question, as a reader asks it?</span><span class="faq__plus" aria-hidden="true"></span></summary>
  <div class="faq__body">
    <p>One-line answer first.</p>
    <ol>
      <li>One step per item. Put app labels in <strong>bold</strong>, exactly as the app shows them.</li>
    </ol>
    <p class="note">An optional note. Use <code>note note--warn</code> for a warning.</p>
    <figure>
      <img src="../assets/faq/android-backup.webp" alt="What the screenshot shows" width="540" height="960" loading="lazy">
      <figcaption>Optional caption.</figcaption>
    </figure>
  </div>
</details>
```

3. Give it a new `id`: lowercase words with hyphens, unique on the page. The id is the deep link (`/faq/#short-question-id`). Never rename a published id, because people share these links.
4. Keep the `<span class="qa__q">` around the question. The search highlights words inside it.
5. Leave out the `<figure>` when there is no screenshot. Put the image in `assets/faq/` as WebP, with synthetic sample data only, and set its real `width` and `height`.
6. Optional: add `data-keywords="words people search for"` to `<details>` for words that are not in the text. Search reads them, and they do not show.
7. Check every label and step against the app code before you publish. Mark an unsure part with `<!-- verify: what to check -->`. Comments never show and are not searched.

To add a topic, copy a whole `<section class="faq-cat">` with a new `data-faq-category` and `id="cat-..."`, and add a chip with the same `data-faq-filter` to the topic list at the top.

### Search

- Search is instant and runs in the browser. It ignores case and accents. Every word must match, in any order, in the question, the answer, the keywords or the topic name. Small words such as "how", "my" and "the" are ignored.
- A typed word matches the start of a word ("sync" finds "syncing"). Some words have synonyms, in `SYNONYMS` in `faq/faq.js`: for example "lost" also finds "stolen", "phone" finds "Android", and "pc" finds "Windows".
- Keys: <kbd>/</kbd> focuses the search, <kbd>Esc</kbd> clears it.
- The search and the topic go into the address (`/faq/?q=lost+phone&cat=lost-device`), so a search can be shared.

The page has no FAQPage structured data (JSON-LD). A static copy would drift from the questions, and plain HTML already gives search engines the full text.
