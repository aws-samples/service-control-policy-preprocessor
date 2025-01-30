import logging
import requests

from scp_preprocessor.application_error import ApplicationError

LOGGER = logging.getLogger('scp-preprocessor')

base_sar_url = 'https://servicereference.us-east-1.amazonaws.com/'

__actions_for_service = {}


def get_actions_for(service_name):
	service_name = service_name.lower()
	actions = __actions_for_service.get(service_name)
	if actions is not None:
		return actions

	__populate_service_manifest()
	url_for_service = __get_url_for_service(service_name)
	if url_for_service is None:
		return []

	LOGGER.info(f'Pulling authorization data from {url_for_service}')
	r = requests.get(url_for_service)
	r.raise_for_status()

	response_as_json = r.json()
	actions = response_as_json['Actions']

	__actions_for_service[service_name] = actions

	return actions


def get_action_key(statement):
	if 'Action' in statement:
		return 'Action'
	elif 'NotAction' in statement:
		return 'NotAction'

	raise ApplicationError('All statements must have Action or NotAction.')


service_manifest = None


def __populate_service_manifest():
	global service_manifest
	if service_manifest is not None:
		return

	service_manifest = {}

	r = requests.get(base_sar_url)
	r.raise_for_status()

	json_response = r.json()
	for service in json_response:
		service_manifest[service['service']] = service['url']


def __get_url_for_service(service_name):
	return service_manifest.get(service_name)
