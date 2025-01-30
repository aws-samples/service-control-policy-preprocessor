import logging
import json

from scp_preprocessor.application_error import ApplicationError

from scp_preprocessor.core import statement_merger, actions, bin_packer, remove_elements
from scp_preprocessor.core.actions import globber, transformer


LOGGER = logging.getLogger('scp-preprocessor')


def run(policy_document, pretty_print, retain_sid, basic, max_policy_bytes):
	# The order of these transformations is important. For example, we can't glob statement actions together until
	# we've expanded all the possible actions in the transformation phase.

	if not isinstance(policy_document, dict):
		raise ApplicationError(f'Policy document must be a dictionary. Value for policy document: {policy_document}')

	# Start by normalizing the statements. We'll strip off the array at the end if it was unnecessary.
	statements = policy_document.get('Statement')
	if isinstance(statements, dict):
		statements = [statements]
		policy_document['Statement'] = statements
	elif not isinstance(statements, list):
		raise ApplicationError('Invalid or missing statement element. Value must be dictionary or list.')

	# remove the optional comments and SID from statements
	elements_to_remove = ["Comments"]
	if not retain_sid:
		elements_to_remove.append("Sid")

	policy_document = remove_elements.remove(policy_document, elements_to_remove)

	if not basic:
		# make sure we expand all globs before running exclusions
		policy_document = globber.expand_globs(policy_document)

		# exclude actions after we've done all expansions
		policy_document = actions.transformer.exclude_actions(policy_document)

	# merge like statements together to save space
	policy_document = statement_merger.merge(policy_document)

	# re-glob the statements to save space
	if not basic:
		policy_document = globber.glob(policy_document)

	statements = bin_packer.bin_pack(policy_document, max_policy_bytes)

	statements_as_json = [json.loads(statement) for statement in statements]
	LOGGER.info(f'Created {len(statements_as_json)} service control policies.')
	if pretty_print:
		return json.dumps(statements_as_json, indent=4)
	else:
		return json.dumps(statements_as_json, separators=(',', ':'))
