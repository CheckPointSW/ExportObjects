from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^program-number$", "^keep-connections-open-after-policy-installation$", "^tags$", "^color$", "^comments$"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
    ]
}

if __name__ == "__main__":
    get_objects("services-rpc", fields)
