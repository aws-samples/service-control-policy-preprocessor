def merge(policy_document):
	statements = policy_document.get('Statement', [])

	statements = _merge_statements(statements)
	if len(statements) > 0:
		policy_document['Statement'] = statements

	return policy_document


def _merge_statements(statements):
	# find any statements that have the same condition, resource, effect, and action and merge the actions
	merged_statements = []
	indices_that_were_merged = set()
	for i in range(len(statements)):
		statement_to_compare = statements[i]
		if i in indices_that_were_merged:
			# this index was already merged, so skip it
			continue

		for j in range(i + 1, len(statements)):
			statement = statements[j]

			if _compare(statement_to_compare, statement):
				merged_statement = _merge_action_or_non_action(statement_to_compare, statement)
				statement_to_compare = merged_statement

				indices_that_were_merged.update([i, j])

		merged_statements.append(statement_to_compare)

	return merged_statements


def _merge_action_or_non_action(statement1, statement2):
	if 'Action' in statement1:
		action_key = 'Action'
	elif 'NotAction' in statement1:
		action_key = 'NotAction'

	statement1_actions = statement1[action_key]
	if not isinstance(statement1_actions, list):
		statement1_actions = [statement1_actions]

	statement2_actions = statement2[action_key]
	if not isinstance(statement2_actions, list):
		statement2_actions = [statement2_actions]

	statement1_actions.extend(statement2_actions)

	statement1[action_key] = statement1_actions

	return statement1


def _compare(statement1, statement2):
	conditions_are_equal = statement1.get('Condition') == statement2.get('Condition')
	resources_are_equal = statement1.get('Resource') == statement2.get('Resource')
	effects_are_equal = statement1.get('Effect') == statement2.get('Effect')

	both_have_not_action_or_action = ('Action' in statement1 and 'Action' in statement2) or \
									 ('NotAction' in statement1 and 'NotAction' in statement2)

	return conditions_are_equal and resources_are_equal and effects_are_equal and both_have_not_action_or_action
