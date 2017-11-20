from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^center-gateways\.[0-9]+\.name$", "^mesh-center-gateways\.[0-9]+\.name$", "^satellite-gateways\.[0-9]+\.name$", "^tags$", "^color$", "^comments$"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
        (r"^center-gateways\.[0-9]+\.name$", [(r"\.name", r"")]),
        (r"^satellite-gateways\.[0-9]+\.name$", [(r"\.name", r"")]),
        (r"^mesh-center-gateways\.[0-9]+\.name$", [(r"\.name", r"")]),
    ]
}

if __name__ == "__main__":
    get_objects("vpn-communities-star", fields)
