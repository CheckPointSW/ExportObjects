from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^tags$", "^color$", "^comments$"],
    "blacklist": ["uid"],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
    ]
}

if __name__ == "__main__":
    get_objects("dynamic-objects", fields)

