import re
from itertools import product


def patternize(pattern, inventory=None, storage_pool=None):
    """Generate list of strings determined by a pattern"""
    if storage_pool:
        pattern = pattern.replace("[pool]", storage_pool)

    if inventory:
        inventory_tokens = re.findall(r"\[[a-zA-Z0-9_]*\]", pattern)
        for token in inventory_tokens:
            pattern = pattern.replace(token, str(inventory[token[1:-1]]))

    tokens = re.findall(r"\[[0-9]-[0-9]\]|\[[a-z]-[a-z]\]|\[[A-Z]-[A-Z]\]", pattern)
    segments = "%s".join(re.split(r"\[[0-9]-[0-9]\]|\[[a-z]-[a-z]\]|\[[A-Z]-[A-Z]\]", pattern))

    if len(tokens) == 0:
        return [pattern]

    combinations = []
    for token in tokens:
        start, stop = token[1:-1].split("-")

        try:
            start = int(start)
            stop = int(stop)
            combinations.append([str(number) for number in range(start, stop+1)])
        except ValueError:
            combinations.append([chr(number) for number in range(ord(start), ord(stop) + 1)])

    return [segments % subset for subset in list(product(*combinations))]


class FilterModule(object):
    """Custom jinja2 filters."""

    def filters(self):
        return {"patternize": patternize}
