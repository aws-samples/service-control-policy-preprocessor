import fnmatch

from scp_preprocessor.core.actions.utils import get_action_key, get_actions_for


def expand_glob(action_glob, actions):
	normalized_action_name = action_glob.lower()
	normalized_actions_for_service = [action.lower() for action in actions]

	normalized_expanded_actions_for_service = fnmatch.filter(normalized_actions_for_service, normalized_action_name)

	expanded_actions_for_service = []
	# get the originally formatted action that matches the normalized action
	for service_action in normalized_expanded_actions_for_service:
		action_index = normalized_actions_for_service.index(service_action)
		expanded_actions_for_service.append(actions[action_index])

	return expanded_actions_for_service


def expand_globs(policy_document):
	statements = policy_document.get('Statement', [])
	for statement in statements:
		action_key = get_action_key(statement)
		actions = statement[action_key]

		if not isinstance(actions, list):
			actions = [actions]

		expanded_actions = []
		for action in actions:
			if action == '*':
				expanded_actions = "*"
				break

			split = action.split(":")
			service_prefix = split[0].lower()

			# there might be more than one colon given other custom commands
			action_name = ':'.join(split[1:])

			if action_name == '*' or action_name.startswith('{'):
				# don't expand if the action is just service:* or is custom syntax
				expanded_actions.append(action)
			else:
				# try to expand any globs
				actions_for_service = get_actions_for(service_prefix)
				actions_for_service = [action['Name'] for action in actions_for_service]
				expanded_actions_for_service = expand_glob(action_name, actions_for_service)
				expanded_actions_for_service = [f'{service_prefix}:{action}' for action in expanded_actions_for_service]
				expanded_actions.extend(expanded_actions_for_service)

		statement[action_key] = expanded_actions

	if len(statements) > 0:
		policy_document['Statement'] = statements

	return policy_document


# transform SCP into a syntax supported by SCPs.  This allows syntax like ec2:*Create*Vpc* which is invalid in an SCP
def glob(policy_document):
	statements = policy_document.get('Statement', [])

	for statement in statements:
		action_key = get_action_key(statement)
		actions = statement[action_key]

		if not isinstance(actions, list):
			actions = [actions]

		actions.sort()
		globbed_actions = try_glob_entire_service(actions)
		globbed_actions = try_glob_actions(globbed_actions)

		if len(globbed_actions) == 1:
			globbed_actions = globbed_actions[0]

		statement[action_key] = globbed_actions

	if len(statements) > 0:
		policy_document['Statement'] = statements

	return policy_document


# see if all actions from a service exist, and if so, replace them with service_name:*
def try_glob_entire_service(expanded_actions):
	new_actions = []
	prefixes_that_have_been_globbed = []
	for action in expanded_actions:
		action_prefix = action.split(":")[0]
		if action_prefix == "*":
			new_actions.append("*")
			continue

		if action_prefix in prefixes_that_have_been_globbed:
			continue

		actions_for_service = [f'{action_prefix}:{action["Name"]}' for action in get_actions_for(action_prefix)]
		# if all actions of a service exist within the expanded actions, replace with *
		if set(actions_for_service).issubset(set(expanded_actions)):
			new_actions.append(f'{action_prefix}:*')
			prefixes_that_have_been_globbed.append(action_prefix)
		else:
			new_actions.append(action)

	return new_actions


# try to combine action names into a singular glob
# e.g. ec2:AcceptTransitGatewayPeeringAttachment and ec2:AcceptTransitGatewayVpcAttachment -> ec2:AcceptTransitGateway*
def try_glob_actions(expanded_actions):
	singly_globbed_actions = [try_glob_single_action(action) for action in expanded_actions]

	# compare n and n+1 and see if they have a shared prefix
	# actions must be sorted first
	globbed_actions = []
	previous_action = singly_globbed_actions[0] if len(singly_globbed_actions) > 0 else None
	for index, action in enumerate(singly_globbed_actions):
		if index == 0:
			continue

		this_action = singly_globbed_actions[index]
		action_pair_result = try_glob_action_pair(previous_action, this_action, expanded_actions)
		if action_pair_result.result not in globbed_actions:
			globbed_actions.append(action_pair_result.result)

		if index == len(singly_globbed_actions) - 1 and action_pair_result.next_action not in globbed_actions:
			globbed_actions.append(action_pair_result.next_action)

		previous_action = action_pair_result.next_action

	if len(singly_globbed_actions) == 1:
		globbed_actions.append(singly_globbed_actions[0])

	return globbed_actions


def try_glob_action_pair(action1, action2, expanded_actions):
	action1_prefix = action1.split(":")[0]
	action2_prefix = action2.split(":")[0]

	# if prefixes are not equal, the two must be different
	if action1_prefix != action2_prefix:
		return GlobActionPairResult(action1, action2)

	glob_proposal = f'{action1_prefix}:*'
	# both actions have the same action_index since prefixes are equal
	action_index = action1.index(":") + 1
	while True:
		common_prefix = get_shortest_common_prefix(action1[action_index:], action2[action_index:])
		if common_prefix is None:
			# no common prefix that does not allow extra actions
			return GlobActionPairResult(action1, action2)

		# remove the existing glob and add a new glob
		glob_proposal = f'{glob_proposal[:-1]}{common_prefix}*'
		if not includes_too_many_actions(glob_proposal, expanded_actions):
			return GlobActionPairResult(glob_proposal, glob_proposal)

		# for the next attempt, increment where the prefix length
		action_index = action_index + len(common_prefix)


class GlobActionPairResult:
	def __init__(self, result, next_action):
		self.result = result
		self.next_action = next_action


# turns an individual action into the shortest possible name with glob to save space
# e.g. iam:SetSecurityTokenServicePreferences -> iam:SetS*
def try_glob_single_action(action_with_prefix):
	split = action_with_prefix.split(":")
	action_prefix = split[0]
	if action_prefix == '*':
		return '*'

	action = split[1]

	# loop through each letter of the action
	for index, char in enumerate(action):
		if index == len(action) - 1:
			# if we've reached the end, don't try to glob
			return action_with_prefix

		substring = action[:index + 1]
		glob_proposal = f'{action_prefix}:{substring}*'
		if not includes_too_many_actions(glob_proposal, [action_with_prefix]):
			return glob_proposal


# verify that the new glob does not include additional actions that did not exist in the source policy
def includes_too_many_actions(glob_proposal, original_actions):
	if glob_proposal == '*':
		return False

	split = glob_proposal.split(':')
	prefix = split[0]
	proposal = split[1]

	action_names = [action["Name"] for action in get_actions_for(prefix)]
	expanded_actions = fnmatch.filter(action_names, proposal)
	expanded_actions = [f'{prefix}:{action}' for action in expanded_actions]
	for expanded_action in expanded_actions:
		if expanded_action not in original_actions:
			return True

	return False


def get_shortest_common_prefix(string1, string2):
	if len(string1) == 0 or len(string2) == 0:
		return None

	if string1[0] == string2[0]:
		return string1[0]

	return None
