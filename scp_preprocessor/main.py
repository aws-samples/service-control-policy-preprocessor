"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import argparse
import logging
import sys
import traceback
import json

from scp_preprocessor.application_error import ApplicationError
from scp_preprocessor.logger import configure_logging
from scp_preprocessor.validation import parse_int
from scp_preprocessor.version import __version__
from scp_preprocessor import transformations

LOGGER = logging.getLogger('scp-preprocessor')


def __load_policy(policy_arg):
	if policy_arg.startswith('file://'):
		filepath = policy_arg.replace('file://', '')
		LOGGER.info(f'Reading file from {filepath}')

		try:
			with open(filepath, 'r') as f:
				return json.load(f)
		except Exception as e:
			raise ApplicationError(f'Failed to load file {filepath}. {str(e)}')
	else:
		try:
			return json.loads(policy_arg)
		except Exception as e:
			raise ApplicationError(f'Failed to load provided policy. {str(e)}')


def main(args=None):
	if args is None:
		args = sys.argv[1:]

	parent_parser = argparse.ArgumentParser(add_help=False)

	parent_parser.add_argument('policy',
		help='The policy to preprocess. You should pass a single policy and allow the tool to optimize the placement '
			 'of statements in the output. Use the file:// prefix to specify a file on disk.')

	parent_parser.add_argument('--max-policy-bytes', help='Set the maximum policy size used for binpacking.',
		default=5120, dest='max_policy_bytes', type=parse_int)

	parent_parser.add_argument('--enable-logging', help='Enable detailed logging. Turn off if you want to use the SCP output.', default=False, action='store_true')

	parent_parser.add_argument('--retain-sid', dest="retain_sid", default=False, action="store_true",
		help='Set this flag to retain statement SIDs. By default, the tool will remove SIDs from all policies to '
			 'optimize space.')
	parent_parser.add_argument('--basic', dest='basic', default=False, action="store_true",
		help='Set this flag to only run basic transformations. This includes SID removal, whitespace removal, and '
			 'statement merging. This ignores action globbing and additional language features.')
	parent_parser.add_argument('--pretty-print', dest='pretty_print', default=False, action="store_true",
		help='Print readable output for debugging. This output is for debugging purposes should not be used to '
					'directly create or modify SCPs.')

	parent_parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

	parser = argparse.ArgumentParser(description='Optimizes SCPs for space and adds some new language constructs.')
	parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

	subparsers = parser.add_subparsers(dest='{process}')

	subparsers.add_parser('process',
		help='Optimizes SCPs for space and adds some new language constructs.', parents=[parent_parser])

	subparsers.required = True

	args = parser.parse_args(args)

	try:
		configure_logging(args.enable_logging)

		policy = __load_policy(args.policy)
		minified_policies = transformations.run(policy, args.pretty_print, args.retain_sid, args.basic, args.max_policy_bytes)
		print(minified_policies)
		exit(0)
	except ApplicationError as e:
		print(f'ERROR: {str(e)}', file=sys.stderr)
		exit(1)
	except Exception as e:
		traceback.print_exc()
		print(f'ERROR: Unexpected error occurred. {str(e)}', file=sys.stderr)
		exit(1)



if __name__ == "__main__":
	import os
	with open(os.path.join('..', 'test_policies', 'example.json')) as f:
		template = json.load(f)
		main(['process',
			  json.dumps(template),
			  '--enable-logging'])
