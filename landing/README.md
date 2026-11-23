# Nuvori landing page

A static site: `index.html`, one stylesheet (`site.css`) and one script (`site.js`) for every page, plus images and fonts in `assets/`, the FAQ, three guides (`browsers/`, `import-passwords/`, `android/`), the privacy policy, the terms and `404.html`. It has no build step and no runtime dependencies, and it loads nothing from other servers. Every page works without JavaScript. For the look, see [Design](#design). For search and speed, see [Search and speed](#search-and-speed).

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

- **Privacy policy and terms of service** are `privacy/index.html` and `terms/index.html` (shared at `/privacy/` and `/terms/`). When an app changes what data it handles, update the policy and its effective date in the same release.
- **The tester sign-up form** (Google Form) is the **Join testing** button in the Android row of `#download` (`#join-testing`) and the footer link of the same name. When the apps leave closed testing, remove both, the `.get__tester` line, and the "Not in every store yet" item in `#limits`.
- **Store status** is the `.get__status` line in each `#download` row: amber for "Under review" or "Closed testing", `.get__status--ok` (green) for "Available". The extension row links to the Chrome Web Store item `lpohaakdindhljdhpofnfmggbfllgdil`, with `assets/qr-chrome-web-store.svg`. **Store links** are each row's buttons and the `data-copy` of its **Copy link** button.
- **QR codes** (`assets/qr-*.svg`) are made from the store URLs. If a URL changes, make the QR code again, and scan it before you publish.
- **No palette file.** The site no longer offers the app's color picker, so it does not use `palette.js`. `scripts/appearance/generate.py` in the Android repository still writes `landing/palette.js` when it runs; nothing loads that file, so delete it or remove those lines from the script.
- **Browser names** (the browser picker in the home hero, the diagram, `/browsers/`, FAQ "Switching browsers") must match what Nuvori for Windows recognizes in `src-tauri/src/browsers.rs` (`classify`). In the picker, each radio's `data-engine` (`chromium`, `firefox`, `safari`, `other`) chooses the answer panel; a note for one browser goes in `NOTES` in `site.js`. Name browsers as text only, never with their logos.
- **Screenshots** in `assets/` are WebP copies of `card_app/docs/assets/screenshots` and `store-assets/`, with synthetic sample data only. `extension-popup-light.webp` and `extension-popup-dark.webp` are 2x renders of the real `extension/popup.html` with a stubbed `chrome.*` API and sample data. A screenshot with a light and a dark version uses two `<img>` elements with `only-light` and `only-dark`.

## FAQ page

The FAQ is `faq/index.html`, shared at `/faq/`. `site.css` styles it. `faq/faq.js` adds search, the topic filter, deep links and the **Copy link** buttons. The script reads the page, so a new question needs no script change. Without JavaScript, every question still shows, and the topic links jump to their section.

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

After you add or change a question, rebuild the FAQPage structured data (see [Search and speed](#search-and-speed)). Deep links such as `/faq/#which-browsers` are fragments of one page, not separate pages: search engines index `/faq/`, which is its canonical URL, and `?q=` and `?cat=` addresses point to it too.

## Design

The site has one idea: the vault stays put, the browsers change. The home hero sets the browsers Nuvori recognizes as large type, and the visitor picks theirs to get its exact setup. Everything else is quiet.

- **Colors** (tokens at the top of `site.css`, light and dark): Porcelain `#f3f5f1` / `#101b15` (page), Shackle `#0a3b22` (ink, buttons; from the logo's shackle), Leaf `#44b048` (the logo's green; used only as a field: the selected browser, the FAQ topic, edges), Stone `#d9e0d6` (lines), Amber `#8a5a00` (store status only). Dark mode has its own values, not an inversion.
- **Type:** Atkinson Hyperlegible Next for everything, Atkinson Hyperlegible Mono only for literal code (URLs, keys). Both are under the SIL Open Font License (`assets/fonts/OFL-*.txt`). The family was drawn so that no letter is mistaken for another (I, l, 1, O, 0), which suits a product where people read passwords and codes.
- **Rules of the system:** sentence case, no labels above headings, no arrows on buttons, no load or scroll animations, real screenshots only, numbers only for real steps.

## Search and speed

### Pages and files

| Path | What it is for |
| --- | --- |
| `/` | Home. JSON-LD: `WebSite`, `Organization`, and one `SoftwareApplication`/`MobileApplication` each for Windows, the extension and Android (all free, `price` 0). |
| `/browsers/` | Searches such as "password manager for Zen / Helium / Arc / Comet", "switch browsers keep passwords". Setup for each browser. |
| `/import-passwords/` | "Import passwords from Chrome / Edge / Brave / Firefox". |
| `/android/` | "Android autofill password manager", "passkeys on Android", Wear OS codes. |
| `/faq/`, `/privacy/`, `/terms/` | JSON-LD `BreadcrumbList`; `/faq/` also `FAQPage`. |
| `404.html` | GitHub Pages serves it for every missing path, at any depth, so it uses root paths (`/assets/...`) only. `noindex`. |
| `robots.txt`, `sitemap.xml` | Crawl rules and the page list. |
| `llms.txt` | A plain-text summary for AI answer engines. Update the facts and the "Status" line when they change. |
| `site.webmanifest`, `favicon.ico`, `assets/favicon-48.png`, `assets/logo-96.webp`, `assets/logo-256.webp` | Icons. The two WebP logos replace the large PNGs on the pages. |

`browsers/`, `import-passwords/` and `android/` use the long-form styles in `site.css` (`.legal`, `.guide`). Name browsers as text only, never with logos, and check every step against the app code, as for the FAQ.

### Rebuild the structured data and the sitemap

Run this in the Android repository after you add a page or change a FAQ question:

```powershell
python scripts/landing/seo.py ..\card_app_windows          # writes faq/index.html (FAQPage) and sitemap.xml
python scripts/landing/seo.py ..\card_app_windows --check  # changes nothing; exit 1 if out of date
```

- The FAQPage JSON-LD sits between the `seo:faq-jsonld` markers in the `<head>` of `faq/index.html`. Never edit it by hand.
- The sitemap lists every `index.html` without `noindex`. `lastmod` is the page's last commit date, or today for a page with uncommitted changes.
- The script also checks that each page has one absolute canonical URL that matches its path, and that every JSON-LD block parses.
- Google shows FAQ rich results only for a few sites, and software rich results only with ratings. Nuvori has no ratings, and the site must never invent them. The markup still helps other search engines and AI answers.

### Every new page needs

1. A unique `<title>` (at most about 60 characters) and a `meta description` (70 to 160 characters).
2. An absolute `<link rel="canonical">`, the `og:*` and `twitter:*` tags with the absolute `og-image.jpg`, and a `BreadcrumbList`.
3. Links to it from at least one other page (the footer is enough), so it is not an orphan.
4. `width`, `height` and `alt` on every image; `loading="lazy"` below the fold.
5. A run of `seo.py`.

### Speed

- **Fonts.** Self-hosted in `assets/fonts/` (about 52 KB together), so no font service sees visitors. Every page preloads `atkinson-hyperlegible-next.woff2`. The `"Atkinson Fallback"` faces in `site.css` scale Arial per weight (size, ascent and descent measured from the font file), so text doesn't move when the font arrives (CLS 0).
- **Hero.** No animation. The `h1` is plain text and is the LCP element.
- **Images.** Screenshots and QR codes load lazily (`loading="lazy"`); QR codes sit in closed `<details>`, so they load only when opened.
- After changing `site.css`, `site.js` or `faq/faq.js`, change their `?v=` in every page.

### Off-site checklist (for the owner)

These need your accounts. Do them once, after the deploy.

1. **Google Search Console.** Add the domain property `santoshkanumuri.com` (DNS TXT record), or a URL-prefix property for `https://nuvori.santoshkanumuri.com/` (HTML tag or file). Submit `https://nuvori.santoshkanumuri.com/sitemap.xml`. Use **URL inspection > Request indexing** for `/`, `/browsers/`, `/android/` and `/import-passwords/`. Check **Enhancements** for structured-data errors after a few days.
2. **Bing Webmaster Tools.** Import the site from Search Console (one click) or verify it the same way. Submit the sitemap. Bing also feeds DuckDuckGo, Yahoo, Ecosia and Copilot answers. Turn on IndexNow if you want faster updates.
3. **Store listings.** Use the same words as the site:
   - Microsoft Store: the description still names only "Chrome, Edge and Brave" for the extension. Add "Zen, Helium, Arc, Comet, Vivaldi, Firefox and other browsers built on Chromium or Firefox". Search terms: keep "password manager", "passkeys", "authenticator"; consider "browser switching" or "offline password manager". Set the **Website** to `https://nuvori.santoshkanumuri.com/` once it loads reliably.
   - Chrome Web Store and Firefox Add-ons: title "Nuvori Password Fill"; put "Works in Zen, Helium, Arc, Comet, Brave, Vivaldi and more" in the first line of the description, and set the homepage URL to the site.
   - Google Play: put "password manager", "autofill" and "passkeys" in the short description, and the site as the website.
4. **Links you can ethically earn.** Never buy links or post fake reviews.
   - AlternativeTo: list Nuvori as an alternative to the browser password managers and to other password managers, with an honest description.
   - Product Hunt: launch once the Windows app is public in the Microsoft Store.
   - Browser communities: the Zen Browser and Helium subreddits or discussions, Arc and Brave community forums, and Firefox add-on collections. Answer real "which password manager works in X?" questions, and say that you made it.
   - GitHub: the site URL in the "About" box of both repositories, and a link in each README.
   - Privacy-focused directories (for example PrivacyTools-style lists) accept submissions with their own review rules.
5. **Check after each deploy.** Open the Rich Results Test and the Schema Markup Validator for `/` and `/faq/`.
