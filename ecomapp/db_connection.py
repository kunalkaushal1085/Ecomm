import pymongo
import os
from dotenv import load_dotenv
load_dotenv()

def get_db_handle(collection_name=None):
    mongo_db_host = os.getenv("MONGO_DB_HOST")
    mongo_db_port = int(os.getenv("MONGO_DB_PORT"))
    mongo_db_name = os.getenv("MONGO_DB_NAME")
    
    client = pymongo.MongoClient(
        host=mongo_db_host,
        port=mongo_db_port,
    )
    db_handle = client[mongo_db_name]
    if collection_name:
        collection = db_handle[collection_name]
        if collection.count_documents({}) == 0:
            collection.insert_one({})
    return db_handle, client


class Database:
    USER_COLLECTION = "user_collection"
    CATEGORY_COLLECTION = "category_collection"
    PRODUCT_COLLECTION = "product_collection"
    Gallery_COLLECTION = "gallery_collection"
    @staticmethod
    def InsertData(db_handle, collection_name, data):
        try:
            collection = db_handle[collection_name]
            result = collection.insert_one(data)  # Insert the document
            return result.inserted_id  # Return the inserted document's ID
        except Exception as e:
            raise Exception(f"Error inserting data into {collection_name}: {str(e)}")
        
    @staticmethod
    def FindOne(db_handle, collection_name, query):
        try:
            collection = db_handle[collection_name]
            return collection.find_one(query)  # Return the document that matches the query
        except Exception as e:
            raise Exception(f"Error finding data in {collection_name}: {str(e)}")
    
    @staticmethod
    def FindAll(db_handle, collection_name, query):
        return list(db_handle[collection_name].find(query))
    

    @staticmethod
    def Update(db_handle, collection_name, query, data):
        try:
            collection = db_handle[collection_name]
            # Ensure we're doing an update and not a full replacement
            return collection.update_one(query, {"$set": data})  # Apply only the specified fields with $set
        except Exception as e:
            raise Exception(f"Error updating data in {collection_name}: {str(e)}")

    @staticmethod
    def Delete(db_handle, collection_name, query):
        try:
            collection = db_handle[collection_name]
            return collection.delete_one(query)
        except Exception as e:
            print(f"Error in delete operation: {e}")
            return None