from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^description$", "^new-name$", "^color$", "^comments$", "^tags$"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
    ]
}

if __name__ == "__main__":
    get_objects("application-site-categories", fields)
