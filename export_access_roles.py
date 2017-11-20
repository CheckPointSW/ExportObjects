from get_objects import get_objects

fields = {
    "whitelist": ["^name$", "^machines$", "^networks$", "^remote-access-clients$", "^tags$", "^users$", "^color$",
                  r"^comments"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
    ]
}

if __name__ == "__main__":
    get_objects("access-roles", fields)
