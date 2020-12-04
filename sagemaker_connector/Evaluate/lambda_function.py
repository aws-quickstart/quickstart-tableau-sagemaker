import boto3
import csv
import io
import json
import logging
import re

###########
# LOGGING # 
###########

logger = logging.getLogger()
logger.setLevel(logging.INFO)

###########
# CONFIGS #
###########

sagemaker = boto3.client('sagemaker-runtime')

#############
# FUNCTIONS #
#############

# Read in Tableau payload and convert it into a CSV for SageMaker AutoPilot
def create_sagemaker_body(event_data):
    try:
        csvio = io.StringIO()
        writer = csv.writer(csvio)
        writer.writerows(zip(*event_data.values()))
        sagemaker_body = csvio.getvalue()
        logger.info(sagemaker_body)
        return sagemaker_body
    except Exception as e:
        logger.error(e, exc_info=True)

# Send data to SageMaker for inference and retrieve results 
def get_sagemaker_response(endpoint_name, content_type, accept, sagemakerbody):
    try:
        response = sagemaker.invoke_endpoint(
            EndpointName=endpoint_name, 
            ContentType=content_type,
            Accept=accept,
            Body=sagemakerbody
        )
        logger.info(response)
        decoded_response = response['Body'].read().decode('utf-8')
        return decoded_response
    except Exception as e:
        logger.error(e, exc_info=True)

# Prepare inference results for Tableau
def serialize_sagemaker_response(sagemaker_response):
    try:
        list_results = re.split(r'\n|,', sagemaker_response)

        if '' in list_results:
            list_results.remove('')
            
        try:
            list_results = [float(i) for i in list_results]
        except ValueError as e:
            logger.info(e, exc_info=True)
        
        return_value = json.dumps(list_results)
        logger.info(return_value)
        serialized_value = json.loads(return_value)
        logger.info(serialized_value)
        return serialized_value
    except Exception as e:
        logger.error(e, exc_info=True)

# Main function
def lambda_handler(event, context):
    logger.info("Event: {0}".format(event))

    if event['script'] == 'return int(1)':
        return 1
    else: 
        content_type = "text/csv"
        accept = "text/csv"
        endpoint_name = event['script'] # Your endpoint name.
        logger.info("Endpoint: {0}".format(endpoint_name))
        event_data = event['data']
        logger.info("Event data: {0}".format(event_data))
    
        try:
            sagemaker_body = create_sagemaker_body(event_data)
            sagemaker_response = get_sagemaker_response(endpoint_name, content_type, accept, sagemaker_body)
            sagemaker_response_serialized = serialize_sagemaker_response(sagemaker_response)
            return sagemaker_response_serialized
        except Exception as e:
            logger.error(e, exc_info=True)     
   