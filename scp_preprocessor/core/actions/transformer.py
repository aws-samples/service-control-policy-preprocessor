import copy
import re

from scp_preprocessor.core.actions.utils import get_action_key


# this regex looks for IAM policies written using exclusions, examples:
# sns:{Exclude:Publish} - captures group1: sns, group2: Exclude:Publish
action_transform_regex = re.compile(r"^(.+):\{(.*?)\}(?:\{(.*?)\})?$")


def exclude_actions(policy_document):
	new_statements = []
	statements = policy_document['Statement']
	for statement in statements:
		copy_of_statement = copy.deepcopy(statement)
		action_key = get_action_key(copy_of_statement)
		actions = copy_of_statement.get(action_key)

		if not isinstance(actions, list):
			actions = [actions]

		excluded_actions = []
		resultant_actions = []
		for action in actions:
			match = action_transform_regex.search(action)
			if match is not None:
				service_prefix = match.group(1)
				action = match.group(2)

				if "exclude:" in action.lower():
					# this is an action exclusion
					action = action[action.index(":") + 1:]
					excluded_actions.append(f'{service_prefix}:{action}')
			else:
				# if no match, just add to list of actions
				resultant_actions.append(action)

		resultant_actions = [action for action in resultant_actions if action not in excluded_actions]
		if len(resultant_actions) > 0:
			copy_of_statement[action_key] = resultant_actions
			new_statements.append(copy_of_statement)

	if len(new_statements) > 0:
		policy_document['Statement'] = new_statements
		return policy_document
	else:
		return {}
