from __future__ import annotations

from html import escape

from markdown_it import MarkdownIt


def render_markdown_preview(markdown: str, first_line: int = 1) -> str:
    """Render untrusted Markdown as safe HTML with source-line anchors."""
    parser = MarkdownIt("commonmark", {"html": False, "linkify": False})
    parser.enable(["table", "strikethrough"])

    def source_attributes(token) -> str:
        if token.map is None:
            return ""
        start, end = token.map
        return (
            f' data-source-start="{first_line + start}"'
            f' data-source-end="{first_line + max(start, end - 1)}"'
        )

    for name in ("fence", "code_block"):
        original = parser.renderer.rules[name]

        def render_code(tokens, index, options, env, rule=original):
            rendered = rule(tokens, index, options, env)
            return f"<div{source_attributes(tokens[index])}>{rendered}</div>"

        parser.renderer.rules[name] = render_code

    def render_image_alt(tokens, index, _options, _env):
        return f'<span class="markdown-image-alt">[图片：{escape(tokens[index].content)}]</span>'

    parser.renderer.rules["image"] = render_image_alt
    tokens = parser.parse(markdown)
    for token in tokens:
        if token.nesting == 1 and token.map is not None:
            start, end = token.map
            token.attrSet("data-source-start", str(first_line + start))
            token.attrSet("data-source-end", str(first_line + max(start, end - 1)))
    return parser.renderer.render(tokens, parser.options, {})
