import copy
import fnmatch
import json

from scp_preprocessor.core.actions.utils import get_actions_for
from scp_preprocessor.tests import MainTest

all_s3_actions = [f's3:{action["Name"]}' for action in get_actions_for('S3')]


class GlobbingTest(MainTest):
	def assert_expected_actions_are_globbed(self, globbed_actions, actions_in_original_policy):
		expanded_actions_not_in_original = []
		expanded_actions_in_original = []

		# using the values from the original policy, get a list of all actions that should and should not
		# appear in the final glob
		for s3_action in all_s3_actions:
			if any([fnmatch.fnmatch(s3_action, action) for action in actions_in_original_policy]):
				expanded_actions_in_original.append(s3_action)
			else:
				expanded_actions_not_in_original.append(s3_action)

		for action in expanded_actions_not_in_original:
			self.assertTrue(all([not fnmatch.fnmatch(action, glob) for glob in globbed_actions]),
				f'{action} should not match any of {globbed_actions}')

		for action in expanded_actions_in_original:
			self.assertTrue(any([fnmatch.fnmatch(action, glob) for glob in globbed_actions]),
				f'{action} should match {globbed_actions}')


class WhenGlobbingActions(GlobbingTest):
	def test_globbing_actions_from_globs(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': [
					's3:Create*',
					"s3:Delete*"
				],
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		first_policy = result[0]
		actions_in_policy = first_policy['Statement']['Action']

		self.assert_expected_actions_are_globbed(
			actions_in_policy,
			['s3:Create*', 's3:Delete*']
		)

	def test_globbing_actions_from_concrete_actions(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': [
					's3:CreateAccessPoint',
					"s3:DeleteObject"
				],
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		first_policy = result[0]
		actions_in_policy = first_policy['Statement']['Action']

		self.assert_expected_actions_are_globbed(
			actions_in_policy,
			['s3:CreateAccessPoint', 's3:DeleteObject']
		)

	def test_globbing_all_actions_in_service(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': copy.deepcopy(all_s3_actions),
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		first_policy = result[0]
		actions_in_policy = first_policy['Statement']['Action']

		self.assert_expected_actions_are_globbed(
			actions_in_policy,
			copy.deepcopy(all_s3_actions)
		)

	def test_globbing_with_exclusions(self):
		all_actions = copy.deepcopy(all_s3_actions)
		all_actions.append(
			's3:{Exclude:PutObject}'
		)
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': all_actions,
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		first_policy = result[0]
		actions_in_policy = first_policy['Statement']['Action']

		all_actions_but_put_object = copy.deepcopy(all_s3_actions)
		all_actions_but_put_object = [action for action in all_actions_but_put_object if action.lower() != 's3:putobject']

		self.assert_expected_actions_are_globbed(
			actions_in_policy,
			all_actions_but_put_object
		)
