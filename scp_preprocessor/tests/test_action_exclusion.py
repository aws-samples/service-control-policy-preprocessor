import json
import fnmatch

from scp_preprocessor.tests import MainTest


class WhenExcludingActionsFromAGlob(MainTest):
	def test_action_is_excluded(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': [
					's3:PutObject*',
					"s3:{Exclude:PutObjectAcl}"
				],
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		first_policy = result[0]
		actions = first_policy['Statement']['Action']

		for action in actions:
			does_match = fnmatch.fnmatch('s3:PutObjectAcl', action)
			self.assertFalse(does_match, f'{action} matches s3:PutObjectAcl')

	def test_all_actions_are_excluded(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': [
					's3:PutObject',
					"s3:{Exclude:PutObject}"
				],
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		self.assertEqual(len(result), 0)

	def test_multiple_actions_excluded(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': [
					'sns:Create*',
					"sns:{Exclude:CreateTopic}",
					"sns:{Exclude:CreateSMSSandboxPhoneNumber}"
				],
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)

		first_policy =  result[0]
		actions = first_policy['Statement']['Action']

		if not isinstance(actions, list):
			actions = [actions]

		for action in actions:
			does_match = fnmatch.fnmatch('sns:CreateTopic', action)
			self.assertFalse(does_match, f'{action} matches sns:CreateTopic')

			does_match = fnmatch.fnmatch('sns:CreateSMSSandboxPhoneNumber', action)
			self.assertFalse(does_match, f'{action} matches sns:CreateSMSSandboxPhoneNumber')

	def test_action_excluded_not_in_any_glob(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': [
					's3:*',
					"sns:{Exclude:CreateTopic}"
				],
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		first_policy = result[0]
		actions = first_policy['Statement']['Action']

		if not isinstance(actions, list):
			actions = [actions]

		for action in actions:
			does_match = fnmatch.fnmatch('sns:CreateTopic', action)
			self.assertFalse(does_match, f'{action} matches sns:CreateTopic')
