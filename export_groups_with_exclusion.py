from get_objects import get_objects


fields = {
    "whitelist": ["^name$", "^include.name$", "^except.name$", "^tags$", "^color$", r"^comments$"],
    "blacklist": [],
    "translate": [
        (r"^include.name$", [(r"\.name", r"")]),
        (r"^except.name$", [(r"\.name", r"")]),
    ]
}
dependency_solver_args = {"singular_type": "group-with-exclusion", "children_keys": ["include", "except"]}
if __name__ == "__main__":
    get_objects("groups-with-exclusion", fields, dependency_solver_args)
