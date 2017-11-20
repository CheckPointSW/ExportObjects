from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^tags$", "^color$", "^comments$", r"^members\.[0-9]+\.name$"],
    "blacklist": ["uid"],
    "translate": [
        # (#1, [(#2, #3)]) -> if field matches with regex #1 then in that field, replace regex #2 with regex #3
        (r"^members\.[0-9]+\.name$", [(r"\.name", r"")])
    ]
}
dependency_solver_args = {"singular_type": "time"}
if __name__ == "__main__":
    get_objects("time-groups", fields, dependency_solver_args)

