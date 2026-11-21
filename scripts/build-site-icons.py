"""Builds the built-in site icon set: src/lib/site-icons.json (and the Android copy).

Inputs (downloaded once, not committed):
  --icons   the unpacked `simple-icons` npm package (data/simple-icons.json, icons/*.svg)
  --tranco  a Tranco top-sites CSV ("rank,domain"), https://tranco-list.eu
  --psl     the Public Suffix List, https://publicsuffix.org/list/public_suffix_list.dat

Only CC0 icons and only domains in the Tranco top --top are used, and only the --max-icons
brands whose best domain ranks highest. A domain gets an icon when
its name (the label before the public suffix) equals the icon's slug or its title in
lower-case letters and digits. An icon's source page is not used: it often names a parent
company or a host (openai.com for "OpenAI Gym"), and a wrong logo is worse than a letter.
A domain that is itself a public suffix (github.io, blogspot.com) never gets an icon, so a
user's own site there does not show the platform's logo.

Output: {"v": 1, "source": ..., "icons": [[title, hex, svgPath], ...], "domains": {domain: index}}
Lookup (same on Windows and Android): try the full host, then drop the leftmost label until
two labels are left: accounts.google.com -> google.com.
"""
import argparse, csv, io, json, re, sys
from urllib.parse import urlparse


def load_psl(path):
    rules, wild, exceptions = set(), set(), set()
    for line in io.open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wild.add(rule[2:])
        else:
            rules.add(rule)
    return rules, wild, exceptions


def public_suffix(host, psl):
    rules, wild, exceptions = psl
    labels = host.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            return ".".join(labels[i + 1:])
        if candidate in rules:
            return candidate
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wild:
            return candidate
    return labels[-1]


def registrable(host, psl):
    host = host.lower().strip(".")
    suffix = public_suffix(host, psl)
    if host == suffix:
        return None
    rest = host[: -len(suffix) - 1]
    return rest.split(".")[-1] + "." + suffix


SHORT_COLLISIONS = {"go.com", "net.com", "rt.com", "max.com", "kit.com", "dm.com", "ada.com", "bit.com", "osu.com", "uv.com", "hal.com", "doi.com", "ana.com", "box.com", "ccc.com", "cbs.com", "acm.com", "lua.com", "osf.com", "yr.com", "vox.com", "bt.com"}


def path_of(svg):
    found = re.search(r'<path d="([^"]+)"', svg)
    return found.group(1) if found else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--icons", required=True)
    parser.add_argument("--tranco", required=True)
    parser.add_argument("--tranco-id", required=True)
    parser.add_argument("--psl", required=True)
    parser.add_argument("--top", type=int, default=100000)
    parser.add_argument("--max-icons", type=int, default=800)
    parser.add_argument("--out", action="append", required=True)
    args = parser.parse_args()

    psl = load_psl(args.psl)
    package = json.load(io.open(f"{args.icons}/package.json", encoding="utf-8"))
    data = json.load(io.open(f"{args.icons}/data/simple-icons.json", encoding="utf-8"))
    icons = [icon for icon in data if icon.get("license", {"type": "CC0-1.0"}).get("type") == "CC0-1.0"]

    by_name = {}
    for icon in icons:
        names = [icon["slug"]]
        if icon["title"].isascii():
            # "AT&T" -> "att". A title with other letters ("ÖBB") would lose them, so it is skipped.
            names.append(re.sub(r"[^a-z0-9]", "", icon["title"].lower()))
        for name in names:
            if len(name) >= 2:
                by_name.setdefault(name, icon["slug"])

    # Only domains people visit: the Tranco top --top. This keeps the set small.
    candidates = {}
    with io.open(args.tranco, encoding="utf-8") as handle:
        for rank, domain in csv.reader(handle):
            if int(rank) > args.top:
                break
            candidates.setdefault(domain.lower(), int(rank))

    domains = {}
    for domain in candidates:
        if registrable(domain, psl) != domain:
            continue  # a public suffix itself (github.io), or not a registrable domain
        name = domain.split(".")[0]
        # Short names collide across countries and products (go.com is Disney, not Go;
        # osu.edu is a university): accept only <name>.com, minus known collisions.
        if len(name) <= 3 and (not domain.endswith(".com") or domain.count(".") != 1 or domain in SHORT_COLLISIONS):
            continue
        if name in by_name:
            # The brand's own name: paypal.com -> PayPal, even when other icons link there.
            domains[domain] = by_name[name]

    # Keep the --max-icons brands whose best domain ranks highest, and only their domains.
    best = {}
    for domain, slug in domains.items():
        best[slug] = min(best.get(slug, candidates[domain]), candidates[domain])
    keep = set(sorted(best, key=best.get)[: args.max_icons])
    domains = {domain: slug for domain, slug in domains.items() if slug in keep}
    used = sorted(keep)
    index = {slug: i for i, slug in enumerate(used)}
    meta = {icon["slug"]: icon for icon in icons}
    table = []
    for slug in used:
        path = path_of(io.open(f"{args.icons}/icons/{slug}.svg", encoding="utf-8").read())
        if not path:
            sys.exit(f"no path in {slug}.svg")
        table.append([meta[slug]["title"], meta[slug]["hex"].upper(), path])
    result = {
        "v": 1,
        "source": f"Simple Icons {package['version']} (CC0-1.0 icons only); domains from Tranco list {args.tranco_id} top {args.top}",
        "icons": table,
        "domains": {domain: index[slug] for domain, slug in sorted(domains.items())},
    }
    text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    for out in args.out:
        io.open(out, "w", encoding="utf-8", newline="\n").write(text)
    print(f"{len(table)} icons, {len(result['domains'])} domains, {len(text) // 1024} KB")


if __name__ == "__main__":
    main()
