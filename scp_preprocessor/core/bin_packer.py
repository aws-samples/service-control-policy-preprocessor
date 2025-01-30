import copy
import json
import re
import logging

from scp_preprocessor.application_error import ApplicationError

LOGGER = logging.getLogger('scp-preprocessor')


def bin_pack(policy_document, max_policy_bytes):
	policy_bin_packer = PolicyBinPacker(policy_document)

	return policy_bin_packer.bin_pack(max_policy_bytes)


class PolicyBinPacker:
	def __init__(self, policy_document):
		self.statements = [
			statement for statement in policy_document.get("Statement", [])
		]

	def bin_pack(self, max_policy_bytes):
		if len(self.statements) == 0:
			return []

		initial_candidate_scp = CandidateScp(max_policy_bytes)
		candidate_scps = [initial_candidate_scp]

		# create a list of tuples with size as the first value and statement as the second value
		# avoiding a dictionary here as it does not allow duplicate keys (same size policies)
		statements_by_size = [
			(_get_statement_size(statement), statement)
			for statement in self.statements
		]
		statements_sorted_by_size = sorted(
			statements_by_size, key=lambda x: x[0], reverse=True
		)

		# bin packing using a first fit decreasing algorithm where we add the largest items first and then try to fit
		# small items afterwards
		for statement in [statements[1] for statements in statements_sorted_by_size]:
			statement_was_fit = False
			for candidate_scp in candidate_scps:
				if candidate_scp.can_fit(statement):
					candidate_scp.add(statement)
					statement_was_fit = True
					break

			if not statement_was_fit:
				new_candidate_scp = CandidateScp(max_policy_bytes)
				if new_candidate_scp.can_fit(statement):
					new_candidate_scp.add(statement)
				else:
					raise ApplicationError(f"Statement too large to fit in an SCP: {statement}")
				candidate_scps.append(new_candidate_scp)

		return [scp.minify_policy(print_minification_stats=True) for scp in candidate_scps]


class CandidateScp:
	def __init__(self, max_policy_bytes):
		self.policy = {"Version": "2012-10-17", "Statement": []}
		self.proposed_policy = copy.deepcopy(self.policy)
		self.max_policy_bytes = max_policy_bytes

	def can_fit(self, statement):
		proposed_policy = copy.deepcopy(self.policy)
		proposed_policy["Statement"].append(statement)
		proposed_minified_string = self.minify_policy(proposed_policy, print_minification_stats=False)

		return len(proposed_minified_string) <= self.max_policy_bytes

	def add(self, statement):
		self.policy["Statement"].append(statement)

	def minify_policy(self, policy=None, print_minification_stats=False):
		if policy is None:
			policy = self.policy

		if print_minification_stats:
			size_before = len(json.dumps(policy, indent=4))
			LOGGER.info(f'Size before minification: {size_before}')

		trimmed_policy = minify_json(policy)

		if print_minification_stats:
			size_after = len(trimmed_policy)
			LOGGER.info(f'Size after minification: {size_after}')
			percent_savings = ((size_before - size_after) / size_before) * 100
			LOGGER.info(f'Saved {int(percent_savings)}% with minification.')

		return trimmed_policy


def minify_json(json_value):
	json_value = _convert_array_with_single_value(json_value)
	value_as_string = json.dumps(json_value)
	trimmed_value = _remove_whitespace(value_as_string)

	return trimmed_value


def _get_statement_size(statement):
	minified_statement = minify_json(statement)
	return len(minified_statement)


def _remove_whitespace(service_control_policy_string):
	trimmed_json = re.sub(r"\s+", "", service_control_policy_string)
	return trimmed_json


# convert arrays with 1 value to a string
def _convert_array_with_single_value(json_value):
	if not isinstance(json_value, dict):
		return json_value

	for key, value in json_value.items():
		if isinstance(value, list):
			if len(value) == 1:
				json_value[key] = value[0]
		elif isinstance(value, dict):
			value = _convert_array_with_single_value(value)
			json_value[key] = value

	return json_value
