from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^start$", "^start-now$", "^end$", "^end-never$", "^hours-ranges$", "^tags$", "^recurrence$", "^color$", "^comments$"],
    "blacklist": ["uid", "domain"],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
    ]
}

if __name__ == "__main__":
    get_objects("times", fields)
