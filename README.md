# AWS Security Day

This DevSecOps pipeline uses AWS DevOps tools , AWS CodeBuild, and AWS CodePipeline along with other AWS services.  It is highly recommended to fully test the pipeline in lower environments and adjust as needed before deploying to production.

### Build and Test: 

The buildspecs and property files for vulnerability scanning using AWS CodeBuild

### Lambda files:

AWS lambda is used to parse the scanning analysis results and post it to AWS Security Hub
* import_findings_security_hub.py: to parse the scanning results, extract the vulnerability details.
* securityhub.py: to post the vulnerability details to AWS Security Hub in ASFF format (AWS Security Finding Format).

### Docker Files:
* Dockerfile contains the instructions of the sampleapplication we are going to build.

### eb_files:
* Dockerrun.aws.json


by RoxsRoss