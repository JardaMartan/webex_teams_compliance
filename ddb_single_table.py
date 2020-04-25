"""
See https://www.trek10.com/blog/dynamodb-single-table-relational-modeling
https://github.com/trek10inc/ddb-single-table-example
"""

import boto3
import argparse
import time
import os
import logging

from dotenv import load_dotenv, find_dotenv

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def get_db_env():
    load_dotenv(find_dotenv())
    tablename = os.getenv("DYNAMODB_TABLE_NAME")
    endpoint_url = os.getenv("DYNAMODB_ENDPOINT_URL")
    dynamodb = boto3.resource('dynamodb', endpoint_url=endpoint_url)
    
    return dynamodb, tablename, endpoint_url

def setup():
    dynamodb, tablename, endpoint_url  = get_db_env()

    logger.info("Creating the \"{}\" table...".format(tablename))
    try:
        table = dynamodb.create_table(TableName=tablename,
            KeySchema=[
                {
                    'AttributeName': 'pk',
                    'KeyType': 'HASH'
                },
                {
                    'AttributeName': 'sk',
                    'KeyType': 'RANGE'
                },
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'pk',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'sk',
                    'AttributeType': 'S'
                },
                {
                'AttributeName': 'data',
                'AttributeType': 'S'
                }
            ],
            GlobalSecondaryIndexes=[
            {
                'IndexName': 'gsi_1',
                'KeySchema': [
                        {
                            'AttributeName': 'sk',
                            'KeyType': 'HASH'
                        },
                        {
                            'AttributeName': 'data',
                            'KeyType': 'RANGE'
                        },
                        ],
                        'Projection': {
                            'ProjectionType': 'ALL'
                        },
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 10,
                            'WriteCapacityUnits': 10
                        }        
                },
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            },
            BillingMode='PROVISIONED',
        )
        logger.info("Waiting for table to create...")
        table.meta.client.get_waiter('table_exists').wait(TableName=tablename)
    except Exception as e:
        logger.info("Create table exception: {}".format(e))
    


def teardown():
    dynamodb, tablename, endpoint_url  = get_db_env()

    logger.info("Deleting the {} table...".format(tablename))
    table = dynamodb.Table(tablename)
    try:
        table.delete()
    except Exception as e:
        logger.error("Delete table exception: {}".format(e))

def get_dynamo_table():
    dynamodb, tablename, endpoint_url  = get_db_env()

    return dynamodb.Table(tablename)
    
def save_db_record(pk, sk, data, **items):
    if isinstance(items, dict):
        for (key, value) in items.items():  # fix 'empty string' problem in DynamoDB
            if value == '':                 # https://forums.aws.amazon.com/thread.jspa?threadID=90137
                items[key] = " "
    try:
        table = get_dynamo_table()
        table_item = {"pk": pk, "sk": sk, "data": data, **items}
        logger.debug("About to store: {}".format(table_item))
        db_response = table.put_item(Item=table_item)
        return db_response
    except Exception as e:
        logger.error("Save DB record exception: {}".format(e))
        
def delete_db_record(pk, sk):
    try:
        table = get_dynamo_table()
        logger.debug("About to delete: {} - {}".format(pk, sk))
        db_response = table.delete_item(Key={"pk": pk, "sk": sk})
        return db_response
    except Exception as e:
        logger.error("Delete DB record exception: {}".format(e))
        
def get_db_record_by_secondary_key(sk):
    try:
        table = get_dynamo_table()
        db_record = table.query(
            IndexName="gsi_1",
            KeyConditionExpression=Key("sk").eq(sk)
        )
        db_response = db_record.get("Items", [])[0]
        return db_response
    except Exception as e:
        logger.error("Get DB record by secondary key exception: {}".format(e))
        
def get_db_record_by_secondary_key_list(sk, data_condition=None):
    try:
        table = get_dynamo_table()
        if data_condition is None:
            db_record = table.query(
                IndexName="gsi_1",
                KeyConditionExpression=Key("sk").eq(sk)
            )
            db_response = db_record.get("Items", [])
        else:
            db_record = table.query(
                IndexName="gsi_1",
                KeyConditionExpression=Key("sk").eq(sk) & Key("data").eq(data_condition)
            )
            db_response = db_record.get("Items", [])
        return db_response
    except Exception as e:
        logger.error("Get DB record by secondary key exception: {}".format(e))
                
def get_db_record_list(pk, data_condition=None):
    try:
        table = get_dynamo_table()
        if data_condition is None:
            db_record = table.query(
                KeyConditionExpression=Key("pk").eq(pk)
            )
        elif pk is not None:
            db_record = table.query(
                IndexName="gsi_1",
                KeyConditionExpression=Key("pk").eq(pk) & Key("data").eq(data_condition)
            )
        else:
            db_record = table.query(
                IndexName="gsi_1",
                KeyConditionExpression=Key("data").eq(data_condition)
            )
        db_response = db_record.get("Items", [])
        return db_response
    except Exception as e:
        logger.error("Get DB record list exception: {}".format(e))
        
def get_db_record(pk, sk):
    try:
        table = get_dynamo_table()
        db_record = table.get_item(Key={"pk": str(pk), "sk": sk})
        if "Item" in db_record:
            ## TODO: check if token is not expired, generate new using refresh token if needed
            return db_record["Item"]
        else:
            return None    
    except Exception as e:
        logger.error("Get DB record exception: {}".format(e))

def query_db_record(pk, sk):
    try:
        table = get_dynamo_table()
        db_record = table.query(
            KeyConditionExpression=Key("pk").eq(pk) & Key("sk").eq(sk)
        )
        db_response = db_record.get("Items", [])[0]
        return db_response
    except Exception as e:
        logger.error("Query DB record list exception: {}".format(e))

def delete_db_record_by_secondary_key(sk):
    db_record = get_db_record_by_secondary_key(sk)
    try:
        db_response = delete_db_record(db_record["pk"], sk)
        return db_response
    except Exception as e:
        logger.error("Delete DB record by secondary key exception: {}".format(e))

def handler():
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", help="create DynamoDB table before loading data", action='store_true')
    parser.add_argument("--teardown", help="delete DynamoDB table", action='store_true')
    args = parser.parse_args()
    if args.teardown:
        teardown()
    elif args.setup:
        setup()
    
if __name__ == "__main__":
    handler()
