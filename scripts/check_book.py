"""Check the local destinations and fragments in a built mdBook."""

import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.anchors = set()
        self.links = []
        self.feed(path.read_text(encoding="utf-8"))

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if attrs.get("id"):
            self.anchors.add(attrs["id"])
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


def check(root):
    pages = {path: Page(path) for path in root.rglob("*.html")}
    if root / "index.html" not in pages:
        raise SystemExit("No generated index.html")
    errors = []
    count = 0
    for path, page in pages.items():
        # mdBook's print view combines chapters, which can have the same headings.
        if path.name in ("print.html", "404.html"):
            continue
        for href in page.links:
            target = urlsplit(href)
            if target.scheme or target.netloc or target.path.startswith("/"):
                continue
            destination = (path.parent / unquote(target.path)).resolve() if target.path else path
            if destination.is_dir():
                destination /= "index.html"
            count += 1
            if not destination.is_file():
                errors.append(f"{path.relative_to(root)}: file not found: {href}")
            elif target.fragment and destination in pages:
                if unquote(target.fragment) not in pages[destination].anchors:
                    errors.append(f"{path.relative_to(root)}: fragment not found: {href}")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Checked {count} local links across {len(pages)} generated HTML pages")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
