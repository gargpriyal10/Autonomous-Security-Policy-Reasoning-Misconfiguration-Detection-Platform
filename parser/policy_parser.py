import json

def load_policy(file_path):
    with open(file_path, 'r') as file:
        policy = json.load(file)
    return policy


def normalize_policy(policy):
    rules = []

    statements = policy.get("Statement", [])

    for stmt in statements:
        effect = stmt.get("Effect")
        actions = stmt.get("Action")
        resources = stmt.get("Resource")

        # convert to list if single value
        if not isinstance(actions, list):
            actions = [actions]
        if not isinstance(resources, list):
            resources = [resources]

        # create atomic rules
        for action in actions:
            for resource in resources:
                rule = {
                    "Effect": effect,
                    "Action": action,
                    "Resource": resource
                }
                rules.append(rule)

    return rules
