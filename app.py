import json
import boto3
import psycopg2

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False
DEFAULT_RESOURCE_TYPE = 'AWS::RDS::DBInstance'

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    return message_type == 'ScheduledNotification'

def evaluate_compliance(control_status):
    return 'NON_COMPLIANT' if control_status != 'PASS' else 'COMPLIANT'

def evaluate_parameters(rule_parameters):
    if 'secretName' not in rule_parameters:
        raise ValueError('The parameter with "secretName" as key must be defined.')
    if not rule_parameters['secretName']:
        raise ValueError('The parameter "secretName" must have a defined value.')
    return rule_parameters

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc


def getCredentials(secretName,event):
    credential = {}
    secret_name = secretName
    client = get_client( service='secretsmanager',event=event)

    get_secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )

    secret = json.loads(get_secret_value_response['SecretString'])

    credential['username'] = secret['username']
    credential['password'] = secret['password']
    credential['host'] = secret['host']
    credential['db'] = "postgres"

    return credential

def get_sat_result(credential, query):
    connection = psycopg2.connect(
        user=credential['username'], password=credential['password'], host=credential['host'], database=credential['db'])
    cursor = connection.cursor()
    cursor.execute(query)
    results = cursor.fetchone()
    cursor.close()
    connection.commit()
    control = {}
    control['status'] = results[0]
    control['attribute'] = results[1]
    control['setting'] = results[2]
    return control

def get_resource_id(resource_name,event):
    AWS_CONFIG_CLIENT = get_client('config', event)
    resource_identifier = AWS_CONFIG_CLIENT.list_discovered_resources(resourceType=DEFAULT_RESOURCE_TYPE,resourceName=resource_name)
    id = resource_identifier['resourceIdentifiers'][0]['resourceId']
    return id
    


def lambda_handler(event, context):
    evaluations = []
    rule_parameters = {}
    invoking_event = json.loads(event['invokingEvent'])
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])
    valid_rule_parameters = evaluate_parameters(rule_parameters)
    if valid_rule_parameters.get('secretName'):
        secretName = valid_rule_parameters['secretName']
    compliance_value = 'NOT_APPLICABLE'
    AWS_CONFIG_CLIENT = get_client('config', event)
    if is_scheduled_notification(invoking_event['messageType']):
        credential = getCredentials(secretName,event)
    query = "SELECT CASE WHEN name='ssl' and setting='on' then 'PASS' ELSE 'FAIL' END as security_check_result,name,setting from PG_SETTINGS where name='ssl';"
    control_status = get_sat_result(credential,query)
    compliance_value = evaluate_compliance(control_status['status'])
    resource_id  = get_resource_id(credential['host'].split('.')[0],event)
    evaluations.append(build_evaluation(resource_id, compliance_value, event, resource_type=DEFAULT_RESOURCE_TYPE))
    print(evaluations)
    response = AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event['resultToken'])