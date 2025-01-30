import json
import sys
import unittest
from contextlib import contextmanager
from io import StringIO

from scp_preprocessor import main


class MainTest(unittest.TestCase):
	def run_test(self, policy):
		with self.assertRaises(SystemExit) as context_manager, self._captured_output() as (out, err):
			main.main(['process', json.dumps(policy)])

		self.assertEqual(0, context_manager.exception.code, err.getvalue())

		result = out.getvalue()
		result = result.replace("\n", "")
		result = result.replace("'", "\"")
		return json.loads(result)



	@contextmanager
	def _captured_output(self):
		new_out, new_err = StringIO(), StringIO()
		old_out, old_err = sys.stdout, sys.stderr
		try:
			sys.stdout, sys.stderr = new_out, new_err
			yield sys.stdout, sys.stderr
		finally:
			sys.stdout, sys.stderr = old_out, old_err
