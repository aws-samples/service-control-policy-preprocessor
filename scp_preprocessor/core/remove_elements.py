

def remove(policy_document, elements_to_remove):
	statements = policy_document.get('Statement', [])
	statements = [__remove_elements_from(statement, elements_to_remove) for statement in statements]

	if len(statements) > 0:
		policy_document['Statement'] = statements

	return policy_document


def __remove_elements_from(statement, elements_to_remove):
	for element in elements_to_remove:
		statement.pop(element, None)

	return statement
