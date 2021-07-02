def lambda_handler(event, context):
    # Info about connector
    return {   
        "description" : "SageMaker Tableau Connector",
        "creation_time" : "0",
        "state_path" : "https://github.com/aws-quickstart/quickstart-interworks-tableau-sagemaker-autopilot/blob/main/README.md",
        "server_version" : "1.0.0",
        "name" : "Tableau SageMaker API Connector", 
        "versions": {
        "v1": {
            "features": {
                "authentication": {
                    "required": True,
                    "methods": {
                        "basic-auth": {}
                        }
                }
            }
        }
    }
}