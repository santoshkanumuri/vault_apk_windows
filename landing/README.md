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
- **The "Under review", "Closed testing" and "Pending review" tags** are the `.tag` elements in the same cards. When the Chrome Web Store listing goes live, replace the disabled `.store--disabled` button with a link like the other cards.
- **QR codes** (`assets/qr-*.svg`) are made from the store URLs. If a URL changes, make the QR code again, and scan it before you publish.
- **`palette.js`** is generated. Run `python scripts/appearance/generate.py <path to card_app_windows>` in the Android repository, and it rewrites this file together with the app palettes.
- **Screenshots** in `assets/` are WebP copies of `card_app/docs/assets/screenshots` and `store-assets/`, with synthetic sample data only.
