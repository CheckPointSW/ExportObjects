from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^gateways\.[0-9]+\.name$", "^tags$", "^color$", "^comments$"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
        (r"^gateways\.[0-9]+\.name$", [(r"\.name", r"")]),
    ]
}

if __name__ == "__main__":
    get_objects("vpn-communities-meshed", fields)
