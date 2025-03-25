from os import error
import os
import stat
from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from ecomapp.db_connection import get_db_handle
from rest_framework.response import Response
import time
from unittest.mock import patch
import bcrypt
from datetime import datetime, timedelta
from django.conf import settings
from django.core.mail import send_mail
from django.test.utils import override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
import jwt
from django.core.files.uploadedfile import SimpleUploadedFile
import jwt
from bson import ObjectId
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from django.utils.timezone import make_aware


# Create your tests here.
class RegisterTestCase(APITestCase):
    
    def setUp(self):
        # Clear the database before each test
        db_handle, client = get_db_handle()

        # db_handle.user_collection.delete_many({})
    def create_user(self):
        
        try:
            unique_email = f"megha@yopmail.com"
            # unique_email = f"admin{int(time.time())}@yopmail.com"
            _data = {
                "first_name":"ram",
                "last_name":"sharma",
                "email":unique_email,
                "password":"12345",
                "username":"ram",
                "role": "seller",
                "phone_number": "1234567893",
                "address": [
                    {
                    "street": "123 Main St",
                    "city": "Springfield",
                    "state": "IL",
                    "country": "USA",
                    "zipcode": "62701"
                    }
                ]
                }
            _response = self.client.post('/api/customer-register', data = _data, format='json')
            print(_response.status_code,'response')
            _data = _response.json()
            print('data',_data)
            self.assertEqual(_response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(_data['data']['email'], unique_email)
            self.assertEqual(_data['message'], "User registered successfully.")
            self.assertEqual(_data['data']['status'], "pending")
            self.assertEqual(_data['data']['first_name'], "John")
            self.assertEqual(_data['data']['last_name'], "Doe")
            self.assertEqual(_data['data']['role'], "seller")
            
        except Exception as e:
            print(e)


    def required_fields(self):
        try:
            # Using data with missing fields (empty email, password, etc.)
            unique_email = f"megha@yopmail.com"
            _data = {
                "first_name": "",
                "last_name": "",
                "email": "",
                "password": "",
                "username": "",
                "role":"",
                "phone_number":""
            }

            # Send POST request to register
            _response = self.client.post('/api/customer-register', data=_data, format='json')
            
            # Get the response data
            _data = _response.json()
            if _data:
                self.assertEqual(_response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(_data,status.HTTP_400_BAD_REQUEST)
                print("Response body:", _data)
            else:
                self.assertEqual(_response.status_code, status.HTTP_200_OK)

        except Exception as e:
            print(e)
    

    def email_already_exists(self):
        try:
            db_handle, client = get_db_handle()
            
            # First, register a user with a unique email
            unique_email = f"megha@yopmail.com"
            _data = {
                "first_name": "john",
                "last_name": "doe",
                "email": unique_email,
                "password": "12345",
                "username": "john123",
                'role':'seller'
            }
            
            # Register the first user
            _response = self.client.post('/api/customer-register', data=_data, format='json')
            _data = _response.json()
            print(_data,'data')
            # Now try to register a second user with the same email
            _data_second = {
                "first_name": "jane",
                "last_name": "doe",
                "email": unique_email,
                "password": "12345",
                "username": "jane123",
                "role":'seller'
            }

            # Attempt registration with the duplicate email
            _response_second = self.client.post('/api/customer-register', data=_data_second, format='json')
            print(_response_second.status_code, 'response')

            # Get the response data for the second request
            _data_second = _response_second.json()

            # Check if the response is indicating an error for the duplicate email
            print("Second response data:", _data_second)
            self.assertEqual(_response_second.status_code, status.HTTP_400_BAD_REQUEST)

            # Check if the error message indicates the email already exists
            self.assertIn("error", _data_second)
            self.assertEqual(_data_second['error'], "User with this email already exists.")
            
            # Optional: Confirm that the email exists in the database (no need to insert it again)
            user_collection = db_handle.user_collection
            existing_user = user_collection.find_one({"email": unique_email})
            self.assertIsNotNone(existing_user)  # Ensure the user exists in the DB

        except Exception as e:
            print(e)


class LoginTest(APITestCase):   
    def setUp(self):
        db_handle, client = get_db_handle()
        user_collection = db_handle.user_collection
        # Create a user for testing login
        self.unique_email = f"admin@yopmail.com"
        self.password = "123456"
        hashed_password = bcrypt.hashpw(self.password.encode('utf-8'), bcrypt.gensalt())
        
        #login seller
        self.seller_email = "megha@yopmail.com"
        self.seller_password = "12345"
        hashed_seller_password = bcrypt.hashpw(self.seller_password.encode('utf-8'), bcrypt.gensalt())
        
        user_collection.insert_one({
            "first_name": "john",
            "last_name": "doe",
            "email": self.unique_email,
            "password": hashed_password,
            "username": "john123",
            "role": "seller",
            "status": "Approve",
        })
        self.invalid_email = "test@gmail.com"
        self.invalid_password = "123456"
        
    def test_seller_login(self):
        """Test login for seller"""
        data = {"email": self.seller_email, "password": self.seller_password}
        response = self.client.post('/api/customer-login', data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'User logged in successfully')
        self.assertEqual(response.data['user']['role'], 'seller')
        
    def test_admin_login(self):
        """Test login for admin"""
        data = {"email": self.unique_email, "password": self.password}
        response = self.client.post('/api/customer-login', data=data, format='json')
        print(response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'User logged in successfully')
        self.assertEqual(response.data['user']['role'], 'admin')

    def invalid_email(self):
        _data = {
            "email": self.invalid_email,  # Using the invalid email
            "password": "12345"
        }
        _response = self.client.post('/api/customer-login', data=_data, format='json')
        _data = _response.json()

        # Assert that the response is for an invalid email
        self.assertEqual(_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid email')
        print("Invalid email login response:", _data)
        
    def invalid_password(self):
        _data = {
            "email": self.unique_email, 
            "password": self.invalid_password
        }
        _response = self.client.post('/api/customer-login', data=_data, format='json')
        _data = _response.json()

        # Assert that the response is for an invalid email
        self.assertEqual(_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid password')
        print("Invalid email login response:", _data)


class PasswordResetRequestTest(APITestCase):
    def setUp(self):
        db_handle, client = get_db_handle()
        user_collection = db_handle.user_collection
        self.existing_email = "megha@yopmail.com"
        self.invalid_email = "test@gmail.com"
        user = user_collection.find_one({"email": self.existing_email.lower()})
        if not user:
            password = "12345"
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_collection.insert_one({
                "first_name": "john",
                "last_name": "doe",
                "email": self.existing_email,
                "password": hashed_password,
                "username": "john123"
            })

    
    def password_reset(self):
        # Test for valid email for password reset
        _data = {"email": self.existing_email}
        _response = self.client.post('/api/forgot-password', data=_data, format='json')
        _data = _response.json()
        # Check the response for valid email
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.assertEqual(_data['message'], 'Password reset link sent successfully.')
        print("Valid password reset response:", _data)
        
    def invalid_email(self):
        # Test for invalid email (email not registered)
        _data = {"email": self.invalid_email}
        _response = self.client.post('/api/forgot-password', data=_data, format='json')
        _data = _response.json()

        # Assert that the response indicates no user found for the given email
        self.assertEqual(_response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(_data['error'], 'No user found with this email.')
        print("Invalid email password reset response:", _data)
        
    
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
    def email_sent(self):
        _data = {"email": self.existing_email}
        _response = self.client.post('/api/forgot-password', data=_data, format='json')
        _data = _response.json()
        # Check the response
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.assertEqual(_data['message'], 'Password reset link sent successfully.')
        print("response body:", _data,status.HTTP_200_OK)
        

class PasswordResetConfirmTest(APITestCase):
    def setUp(self):
        db_handle, client = get_db_handle()
        # Set up MongoDB collections and mock data
        self.user_id = "60420a8c-a241-4f49-836b-00e717b16281"
        self.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjdkY2ZjMGUyYWI4MGQyMWU0ODMxMmNiIiwiZW1haWwiOiJtZWdoYUB5b3BtYWlsLmNvbSIsInVzZXJuYW1lIjoicmFtIiwiZXhwIjoxNzQyNjM2MTQ1LCJpYXQiOjE3NDI1NDk3NDV9.ap7h9_-eM49UG27JXSg9pvbAomos9UbFYofazvL63Sc" #add token here
        self.new_password = "12345"
        self.confirm_password = "12345"
        self.invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjdkY2ZjMGUyYWI4MGQyMWU0ODMxMmNiIiwiZW1haWwiOiJtZWdoYUB5b3BtYWlsLmNvbSIsInVzZXJuYW1lIjoicmFtIiwiZXhwIjoxNzQyNjI5MTM3LCJpYXQiOjE3NDI1NDI3Mzd9.gOvjZSOLQMHzB0KP_ghvX1Ja_YBk9MHQvUmtNT3xHi2"
        self.expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNjdkY2ZjMGUyYWI4MGQyMWU0ODMxMmNiIiwiZW1haWwiOiJtZWdoYUB5b3BtYWlsLmNvbSIsInVzZXJuYW1lIjoicmFtIiwiZXhwIjoxNzQyNjI5MTM3LCJpYXQiOjE3NDI1NDI3Mzd9.gOvjZSOLQMHzB0KP_ghvX1Ja_YBk9MHQvUmtNT3xHi3"
        # Insert user into database
        hashed_password = bcrypt.hashpw("oldpassword".encode('utf-8'), bcrypt.gensalt())
        db_handle.user_collection.insert_one({"_id": self.user_id, "password": hashed_password})

        # Insert token into reset_token_collection
        expiry_time = make_aware(datetime.now() + timedelta(minutes=10))  # Valid for 10 minutes
        db_handle.reset_token_collection.insert_one({
            "user_id": self.user_id,
            "token": self.token,
            "expiry": expiry_time
        })
    
    def test_invalid_token(self):
        # Test with an invalid token
        url = '/api/reset-password'
        data = {
            'token': self.invalid_token,
            'new_password': self.new_password,
            'confirm_password': self.confirm_password
        }
        # Send the request to reset the password with an invalid token
        response = self.client.post(url, data, format='json')
        _data =response.json()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid or expired token.')
        print("Invalid token response:", _data)
        
    def test_expired_token(self):
        # Test with an expired token
        url = '/api/reset-password'
        data = {
            'token': self.expired_token,
            'new_password': self.new_password,
            'confirm_password': self.confirm_password
        }
        # Send the request to reset the password with an expired token
        response = self.client.post(url, data, format='json')
        _data = response.json()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid or expired token.')
        
    def token_is_valid(self):
        # Test with a valid token
        url = '/api/reset-password'
        data = {
            'token': self.token,
            'new_password': self.new_password,
            'confirm_password': self.confirm_password
        }
        # Send the request to reset the password with a valid token
        response = self.client.post(url, data, format='json')
        _data = response.json()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(_data['message'], 'Password has been reset successfully.')
        print("Valid token response:", _data)


# Get Admin Token
def get_admin_token(client, email, password):
    """
    Helper function to log in as an admin and retrieve the authentication token.
    Replace this with your actual login mechanism.
    """
    login_url = reverse('customer-login')  # Replace 'login' with your actual login URL name
    data = {'email': email, 'password': password}
    response = client.post(login_url, data, format='json')
    assert response.status_code == status.HTTP_200_OK # or whatever status your login returns
    return response.data['token']

        

# Admin add category Test Case
class AdminAddCategory(APITestCase):
    def setUp(self):
        db_handle, client = get_db_handle()
        self.user_collection = db_handle.user_collection
        self.client = APIClient()
        try:
            self.admin_token = get_admin_token(self.client, 'admin@yopmail.com', '123456')  # Get the admin token
        except Exception as e:
            print(f"Error during setUp: {e}")
            raise

    def test_add_category_success(self):
        """
        Test case to verify that an admin can successfully add a new category
        with multiple images.
        """
        login_url = '/api/customer-login'
        category_url = '/api/add-category'  # Replace with the actual URL for adding categories

        # Authenticate and get the admin token
        _data = {
            "email": 'admin@yopmail.com',  # Using the valid admin email
            "password": "123456"
        }
        _response = self.client.post(login_url, data=_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)

        # Assuming the response contains the token, extract it
        self.admin_token = _response.data.get('token')
        
        # Ensure the token is returned in the response
        self.assertIsNotNone(self.admin_token, "Token is missing in login response")
        
        # Prepare test data for category creation
        data = {
            # 'title': 'Diamond Jewelry',
            'short_description': 'A brief description for the new category.',
            'product_category': 'silver',  # Ensure this is unique for the test
            'image': 'tiger.avif',
        }
        image_name = 'tiger.avif' 
        # Prepare image files (create dummy files)
        image_path = os.path.join(settings.MEDIA_ROOT, 'category_images', image_name)
        print(image_path)
        if not os.path.exists(image_path):
            self.fail(f"Test image not found at {image_path}")
        img = open(image_path, 'rb')
        files = {'image': img}

        # Update the 'data' dictionary with the files
        data.update(files)
        
        # Set the authorization header with the admin token
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')

        try:
            _response = self.client.post('/api/add-category', data, format='multipart')
            _data = _response.json()
            print(_data,'data')
            # Assertions
            self.assertEqual(_response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(_data['message'], "Category added successfully.")
            self.assertIsInstance(_data['data']['image'], list)
            self.assertEqual(len(_data['data']['image']), 1)  # Check if all images are in response
        finally:
            img.close()
        

    def test_add_category_missing_fields(self):
        """
        Test case to verify that the API returns an error if the required fields are missing.
        """
        login_url = '/api/customer-login'
        category_url = '/api/add-category'
        _data = {
            "email": 'admin@yopmail.com',  # Using the valid admin email
            "password": "123456"
        }
        _response = self.client.post(login_url, data=_data, format='json')
        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)

        # Assuming the response contains the token, extract it
        self.admin_token = _response.data.get('token')
        
        # Ensure the token is returned in the response
        self.assertIsNotNone(self.admin_token, "Token is missing in login response")
        # Prepare test data with missing fields
        data = {
            'title': '',  # Empty title
            'short_description': 'this is image',
            'product_category': '', # Empty product type
        }
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        # Make the API request
        response = self.client.post(category_url, data, format='json')
        response_data = response.json()
        # Assert the response status code
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_data['error'], 'At least one image is required.')
        print("Valid token response:", response_data)


# Get categories according to product type
class GetCategoriesByProductType(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_get_categories_by_product_type(self):
        login_url = '/api/customer-login'
        url = '/api/get-category'
        _data = {
            "email": 'admin@yopmail.com',  # Using the valid admin email
            "password": "123456"
        }
        _response = self.client.post(login_url, data=_data, format='json')

        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.admin_token = _response.data.get('token')
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AddProductTestCase(APITestCase):
    def setUp(self):
        
        db_handle, client = get_db_handle()
        self.user_collection = db_handle.user_collection
        self.client = APIClient()
        try:
            self.admin_token = get_admin_token(self.client, 'megha@yopmail.com', '12345')  # Get the admin token
        except Exception as e:
            print(f"Error during setUp: {e}")
            raise
        
    def test_add_product_success(self):
        """
        Test case to verify that an admin can successfully add a new product
        with multiple images.
        """
        self.add_product_url = '/api/add-product'
        image = SimpleUploadedFile("test_image.jpg", b"file_content", content_type="image/jpeg")
        # Load image paths
        featured_image = SimpleUploadedFile("featured_image.jpg", b"file_content", content_type="image/jpeg")
        gallery_image1 = SimpleUploadedFile("test_image1.jpg", b"file_content", content_type="image/jpeg")
        gallery_image2 = SimpleUploadedFile("test_image2.jpg", b"file_content", content_type="image/jpeg")
        self.category_id = '67dd38ee8b73ef44a2e1dbfa'
        data = {
            'name': 'product1',
            'featured_image':[image],
            'short_description': 'A brief description for the new product.',
            'product_category': 'silver1234',
            'category_id': self.category_id,
            'price': 30,
            'discount_price': 10,
            'tag': 'Hot',
            'sizes': 'M',
            'colors': 'Red',
            'gallery_images':[image],

        }
            

        files = {
            'featured_image': featured_image,  # ✅ Sending as a file, NOT a string
            'gallery_images': [gallery_image1, gallery_image2]  # ✅ Sending multiple images
        }

        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        # 🟢 Send POST request
        _response = self.client.post(self.add_product_url, data=data, format='multipart', files=files)

        # 🟢 Debugging: Print response
        _data = _response.json()
        print("Response Data:", _data)

        # 🟢 Assertions
        self.assertEqual(_response.status_code, status.HTTP_201_CREATED, f"Unexpected response: {_data}")
        self.assertEqual(_data['message'], "Product added successfully")

    def test_add_product_missing_fields(self):
        """Test adding a product with missing required fields"""
        self.add_product_url = '/api/add-product'
        self.category_id ='67dd38ee8b73ef44a2e1dbfa'
        data = {
            'name': '', 
            'featured_image': '',
            'short_description': 'This is a test description',
            'price': '',
            'discount_price': '',
            'tag': '',
            'sizes': '',
            'colors': '',
            'category_id': self.category_id,  # ✅ Ensure category_id is assigned
            'sku': '',
        }

        # ✅ Debug: Check if the token is properly set
        print(f"Request header Token: {self.admin_token}")
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        response = self.client.post(self.add_product_url, data, format='json')

        # ✅ Debug: Print response status and content
        print(response.status_code, response.json(), 'response')

        # ✅ Ensure the correct error code is returned
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)


# Admin can get user list
class GetUserListTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        login_url = '/api/customer-login'

        # Authenticate and get the admin token
        self.admin_data = {
            "email": 'admin@yopmail.com',  # Using the valid admin email
            "password": "123456"
        }
        _response = self.client.post(login_url, data=self.admin_data, format='json')
        print("Admin Login Response:", _response.status_code, _response.data)
        self.assertEqual(_response.status_code, status.HTTP_200_OK, f"Admin login failed: {_response.data}")
    
        self.admin_token = _response.data.get('token')
        self.assertIsNotNone(self.admin_token, "Admin token is missing in login response")
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        # Seller login and token retrieval
        seller_data = {
            "email": 'megha@yopmail.com',
            "password": "12345"
        }
        seller_response = self.client.post(login_url, data=seller_data, format='json')
        print("Seller Login Response:", seller_response.status_code, seller_response.data)
        self.assertEqual(seller_response.status_code, status.HTTP_200_OK, f"Seller login failed: {seller_response.data}")
        self.seller_token = seller_response.data.get('token')
        self.assertIsNotNone(self.seller_token, "Seller token is missing in login response")

        # Buyer login and token retrieval
        buyer_data = {
            "email": 'buyer@gmail.com',
            "password": "123456"
        }
        buyer_response = self.client.post(login_url, data=buyer_data, format='json')
        print("Buyer Login Response:", buyer_response.status_code, buyer_response.data)
        self.assertEqual(buyer_response.status_code, status.HTTP_200_OK, f"Buyer login failed: {buyer_response.data}")
        self.buyer_token = buyer_response.data.get('token')
        self.assertIsNotNone(self.buyer_token, "Buyer token is missing in login response")

    def test_admin_get_user_list(self):
        """Test that an admin can successfully fetch user list"""
        get_user_list_url = '/api/get-user-list'  # Ensure this is correct

        # Fix: Use 'GET' instead of 'POST'
        response = self.client.get(get_user_list_url, format='json')

        print("Admin User List Response:", response.status_code, response.data)
        # Ensure the request is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('buyers', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], "Users fetched successfully.")


    def test_seller_get_own_list(self):
        """Test that a seller can fetch only their own user list"""
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.seller_token}')
        response = self.client.get('/api/get-user-list')
        print("Seller User List Response:", response.status_code, response.data)
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('message', response.data)
        # self.assertEqual(response.data['message'], "Users fetched successfully.")

    def test_buyer_get_own_list(self):
        """Test that a buyer can fetch only their own user list"""
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.buyer_token}')
        response = self.client.get('/api/get-user-list')
        print("Buyer User List Response:", response.status_code, response.data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], "Users fetched successfully.")

#     def test_invalid_token(self):
#         """Test the case where an invalid token is used"""
#         get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
#         self.client.credentials(HTTP_AUTHORIZATION='Token invalid_token')

#         response = self.client.post(get_user_list_url, format='json')
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#         self.assertIn('error', response.data)
#         self.assertEqual(response.data['error'], 'Please login again or check the token.')

#     def test_user_not_found(self):
#         """Test the case where the seller ID is not found"""
#         get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
#         invalid_token = 'Bearer invalid_user_token'  # Use an invalid token to simulate this scenario
#         self.client.credentials(HTTP_AUTHORIZATION=invalid_token)

#         response = self.client.post(get_user_list_url, format='json')
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertIn('error', response.data)
#         self.assertEqual(response.data['error'], 'User not found.')


# # #Admin can get all product list and seller get own product list
class GetAllProductListTestCase(APITestCase):

    def setUp(self):
        """Set up the test environment and create test users."""
        self.client = APIClient()
        login_url = '/api/customer-login'

        # Authenticate and get the admin token
        admin_data = {
            "email": 'admin@yopmail.com',  # Using the valid admin email
            "password": "123456"
        }
        _response = self.client.post(login_url, data=admin_data, format='json')
        print(_response,'response')
        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.admin_token = _response.data.get('token')
        self.assertIsNotNone(self.admin_token, "Admin token is missing in login response")

        # Seller login and token retrieval
        seller_data = {
            "email": 'megha@yopmail.com',
            "password": "12345"
        }
        seller_response = self.client.post(login_url, data=seller_data, format='json')
        print(seller_response.data,'seller response')
        # Check if seller login is successful
        self.assertEqual(seller_response.status_code, status.HTTP_200_OK)
        self.seller_token = seller_response.data.get('token')
        self.assertIsNotNone(self.seller_token, "Seller token is missing in login response")

        # Create products in the database for testing
        self.product_data_1 = {
            "name": "Product A",
            "price": 100,
            "sellert_id": '67ac929d42c14b9853f2655e',  # Simulating seller ID
            "category_id": "677630ae44caa07cb62b01b2",
        }
        self.product_data_2 = {
            "name": "Product B",
            "price": 200,
            "sellert_id": '67ac929d42c14b9853f2655e',  # Another seller ID
            "category_id": "677630ae44caa07cb62b01b2",
        }

        # Save products to the database via the product creation API (this assumes a URL exists for product creation)
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        self.client.post('/api/add-product', self.product_data_1, format='json')
        self.client.post('/api/add-product', self.product_data_2, format='json')
        
    def test_admin_can_get_all_products(self):
        """Test that admin can get the list of all products."""
        get_product_list_url = '/api/get-all-product-list'  # The endpoint to fetch all products
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')

        response = self.client.get(get_product_list_url, format='json')

        print(response.json(), 'Admin get products response')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('status'), 'success')
        self.assertIn('products', response.data)
        # self.assertEqual(len(response.data['products']), 2)
    
    def test_seller_can_get_their_own_products(self):
        """Test that seller can only see their own products."""
        get_product_list_url = '/api/get-all-product-list'  # The endpoint to fetch the seller's products
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.seller_token}')
        # Test the API endpoint for getting seller's products
        response = self.client.get(get_product_list_url, format='json')
        print(response.json())
        # Assert that the status code is OK and seller sees only their own product
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('products', response.data)

    def test_no_products_found(self):
        """Test API response when fetching products for a seller"""
        login_url= '/api/customer-login'
        product_list_url='/api/get-all-product-list'
        seller_data = {
            "email": 'megha@yopmail.com',
            "password": "12345"
        }
        # Step 1: Seller Login
        login_response = self.client.post(login_url, data=seller_data, format='json')
        
        # Debugging login response
        print("Login Response:", login_response.data)

        # Assert successful login
        self.assertEqual(login_response.status_code, status.HTTP_200_OK, "Login failed! Check credentials or API response.")
        
        # Extract authentication token
        seller_token = login_response.data.get('token')
        self.assertIsNotNone(seller_token, "No token received, login failed.")

        # Step 2: Set Authorization Token
        self.client.credentials(HTTP_AUTHORIZATION=f'{seller_token}')

        # Step 3: Fetch All Products
        response = self.client.get(product_list_url, format='json')
        
        # Debugging product list response
        print("Product List Response:", response.data)

        # Step 4: Handle API Response
        if response.status_code == status.HTTP_200_OK:
            self.assertIn('products', response.data, "Response does not contain 'products' key.")
            self.assertGreater(len(response.data['products']), 0, "Expected products, but none found.")
            print("✅ Products found:", response.data['products'])
        
        elif response.status_code == status.HTTP_404_NOT_FOUND:
            self.assertIn('error', response.data, "Response does not contain 'error' key.")
            self.assertEqual(response.data['error'], 'No products found.', "Unexpected error message.")
            print("⚠️ No products found.")

        else:
            self.fail(f"❌ Unexpected response status: {response.status_code} - {response.data}")




