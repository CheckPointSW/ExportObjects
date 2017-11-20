from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^ip-address$", "^ipv4-address$", "^ipv6-address$", "^color$", "^comments$",
                  "^tags$", "^host-servers$"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
        (r"^groups\.[0-9]+\.name$", [(r"\.name", r"")])
    ]
}

if __name__ == "__main__":
    get_objects("hosts", fields)
