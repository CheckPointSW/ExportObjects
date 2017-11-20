from get_objects import get_objects

fields = {
    "whitelist": [r"^name$", r"^applications-and-url-filtering$", r"^data-awareness$", r"^nat-settings",
                  r"^detect-using-x-forward-for$", r"^firewall$", r"^mobile-access$", r"^show-parent-rule$",
                  r"^shared$", r"^tags$", r"^color$", r"^comments$"],
    "blacklist": [],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
    ]
}

if __name__ == "__main__":
    get_objects("access-layers", fields)
