import json

from scp_preprocessor.tests import MainTest


class WhenRemovingElementsFromStatement(MainTest):
	def test_comments_and_sid_are_removed(self):
		policy = {
			'Version': '2012-10-17',
			'Statement': [{
				'Comments': ['abc', 'def', 'hij'],
				'Sid': 'abcdef',
				'Effect': 'Allow',
				'Action': 's3:PutObject',
				'Resource': '*'
			}]
		}

		result = self.run_test(policy)
		self.assertEqual(len(result), 1)

		first_policy = result[0]
		self.assertTrue(isinstance(first_policy['Statement'], dict))
		self.assertNotIn('Sid', first_policy['Statement'])
		self.assertNotIn('Comments', first_policy['Statement'])
