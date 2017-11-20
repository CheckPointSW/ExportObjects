from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^subnet4$", "^subnet6$", "^mask-length4$", "^mask-length6$", "^nat-settings$", "^tags$", "^broadcast$", "^color$", "^comments$"],
    "blacklist": ["uid", "domain"],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
        (r"^groups\.[0-9]+\.name$", [(r"\.name", r"")])
    ]
}

if __name__ == "__main__":
    get_objects("networks", fields)
