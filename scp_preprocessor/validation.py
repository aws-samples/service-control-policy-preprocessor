import argparse


def parse_int(value):
	try:
		return int(value)
	except ValueError:
		raise argparse.ArgumentTypeError('Value must be integer')
