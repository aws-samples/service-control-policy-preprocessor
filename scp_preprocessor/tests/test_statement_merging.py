import copy
import json

from scp_preprocessor.tests import MainTest


class WhenMergingLikeStatements(MainTest):
	def test_merges_like_statements(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}, {
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}]
		}

		expected_policy = {
			'Version': '2012-10-17',
			'Statement': {
				'Effect': 'Allow',
				'Action': ['s3:GetObject', 's3:PutObject'],
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}
		}

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)


class WhenMergingUnlikeStatements(MainTest):
	def test_does_not_merge_different_effects(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}, {
				'Effect': 'Deny',
				'Action': 's3:GetObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}]
		}

		expected_policy = copy.deepcopy(policy)

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)

	def test_does_nothing_if_statements_not_array(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': {
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}
		}

		expected_policy = copy.deepcopy(policy)

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)

	def test_does_not_merge_different_resources(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': 'arn:aws:s3:::my-bucket',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}, {
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}]
		}

		expected_policy = copy.deepcopy(policy)

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)

	def test_does_not_merge_different_condition_keys(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalAccount": "1111"
					}
				}
			}, {
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}]
		}

		expected_policy = copy.deepcopy(policy)

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)

	def test_does_not_merge_action_and_not_action(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'NotAction': 's3:PutObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}, {
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}]
		}

		expected_policy = copy.deepcopy(policy)

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)

	def test_does_not_merge_different_condition_keys(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalAccount": "1111"
					}
				}
			}, {
				'Effect': 'Allow',
				'Action': 's3:GetObject',
				'Resource': '*',
				"Condition": {
					"StringEquals": {
						"aws:PrincipalArn": "1111"
					}
				}
			}]
		}

		expected_policy = copy.deepcopy(policy)

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertEqual(first_policy, expected_policy)
