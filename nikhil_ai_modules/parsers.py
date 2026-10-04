"""Small standard-library HTML parsers used by passive/read-only modules."""
from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict] = []
        self._in_title = False
        self._title_chunks: List[str] = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self._in_title = True
        elif tag.lower() == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag.lower() == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif tag.lower() == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "GET").upper(),
                "enctype": attributes.get("enctype", ""),
                "fields": [],
                "has_file_input": False,
            }
            self.forms.append(self._form)
        elif tag.lower() in ("input", "textarea", "select") and self._form is not None:
            field = {
                "name": attributes.get("name", ""),
                "type": attributes.get("type", "text").lower(),
                "autocomplete": attributes.get("autocomplete", ""),
                "accept": attributes.get("accept", ""),
                "maxlength": attributes.get("maxlength", ""),
            }
            if field["type"] == "hidden":
                # Kept in memory only so an explicitly approved test login can
                # include a CSRF field; callers must never return or persist it.
                field["value"] = attributes.get("value", "")
            self._form["fields"].append(field)
            if field["type"] == "file":
                self._form["has_file_input"] = True
        elif tag.lower() == "button" and self._form is not None:
            self._form["fields"].append({"name": attributes.get("name", ""), "type": "button"})

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False
            self.title = " ".join("".join(self._title_chunks).split())[:300]
        elif tag.lower() == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self._title_chunks.append(data)


def parse_page(html: str) -> PageParser:
    parser = PageParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    return parser
