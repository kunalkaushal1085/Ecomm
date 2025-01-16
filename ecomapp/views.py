from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from django.core.mail import send_mail
import bcrypt
from datetime import datetime, timedelta, timezone
import uuid
from .db_connection import get_db_handle
import os
from .serializers import *
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
import jwt
from . db_connection import Database
from django.conf import settings
from pathlib import Path



# Create your views here.

class UserRegistrationView(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        username = data.get('username')
        role = data.get('role')
        phone_number = data.get('phone_number')
        address = data.get('address')

        # if not email or not password or not first_name or not last_name or not username:
        if not email or not password or not first_name or not last_name or not username or not role or not phone_number:
            return Response({"error": "Missing required fields."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate `role` value
        if role not in ['seller', 'buyer','admin']:
            return Response({"message": "Role must be 'seller' or 'buyer' or 'admin'."})
        db_handle, _ = get_db_handle()  # Get the MongoDB database handle
        super_admin_exists = Database.FindOne(db_handle, Database.USER_COLLECTION, {"role": "admin"})
        if role == 'admin' and super_admin_exists:
            return Response({"error": "Admin has already been created."}, status=status.HTTP_400_BAD_REQUEST)
        if Database.FindOne(db_handle, Database.USER_COLLECTION, {"email": email}):
            return Response({"status": status.HTTP_400_BAD_REQUEST,"error": "User with this email already exists."})
        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if role == "admin" and not super_admin_exists:
            status_value  = True  # First admin will be set to True
        elif role == "seller":
            status_value  = "pending"
        else:
            status_value  = False
        user_data = {
            "user_id": user_id,
            "email": email,
            "password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "role": role,
            "phone_number": phone_number,
            "address": address,
            "status": status_value ,
            "created_at": datetime.utcnow().isoformat(), 
            "updated_at": datetime.utcnow().isoformat()
        }
        try:
            inserted_id = Database.InsertData(db_handle, Database.USER_COLLECTION, user_data)
            user_data['_id'] = str(inserted_id)
            return Response({
                "status": status.HTTP_201_CREATED,
                "message": "User registered successfully.",
                "data": user_data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if not email or not password:
                return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

            db_handle, _ = get_db_handle()  # Get the MongoDB database handle
            user_collection = db_handle.user_collection

            # Find the user by email
            user = user_collection.find_one({
                "$or": [
                    {"email": email.lower()},
                    {"username": email}
                ]
            })
            print(user,'???')
            if user:
                if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                    print(">>>>>>>>>",user.get('status'))
                    if user['role'] == 'seller' and user.get('status') == 'pending':
                        print('insdie role')
                        return Response({
                            'status': status.HTTP_403_FORBIDDEN,
                            'message': 'Your account is pending approval by the admin. You cannot log in yet.'
                        }, status=status.HTTP_403_FORBIDDEN)
                    payload = {
                        'user_id': str(user['_id']),  # Convert _id to string
                        'email': user['email'],
                        'username': user['username'],
                        'exp': datetime.utcnow() + timedelta(days=1),  # Token expiry (1 hour)
                        'iat': datetime.utcnow()  # Issued at time
                        
                    }
                    secret_key = os.getenv('JWT_SECRET_KEY', os.getenv('SECRET_KEY'))
                    access_token = jwt.encode(payload, secret_key, algorithm='HS256')
                    user_data = {
                        "_id": str(user['_id']),  # Ensure _id is a string
                        "email": user['email'],
                        "first_name": user['first_name'],
                        "last_name": user['last_name'],
                        "role": user['role'],
                        "username": user['username']
                    }
                    return Response({
                        'status': status.HTTP_200_OK,
                        'message': 'User logged in successfully',
                        'token': access_token,
                        'user': user_data,
                        'base_url': os.getenv("FRONTEND_URL")
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'status': status.HTTP_400_BAD_REQUEST,
                        'message': 'Invalid password'
                    }, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid email'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print(str(e),"error")
            return Response({
                'status': status.HTTP_400_BAD_REQUEST,'message':str(e)},status=status.HTTP_400_BAD_REQUEST)

# Admin API to approve seller accounts
class AdminApproveSellerView(APIView):
    def post(self, request):
        try:
            seller_id = request.data.get('seller_id')
            status_value = request.data.get('status') 
            if not seller_id:
                return Response({'error': 'Seller ID is required.'}, status=status.HTTP_400_BAD_REQUEST)
            if status_value.lower() not in ['approve', 'decline']:
                return Response({'error': 'Invalid status. It should be either "approve" or "decline".'}, status=status.HTTP_400_BAD_REQUEST)
            status_value = status_value.title()

            db_handle, _ = get_db_handle()

            # Find the seller by ID
            seller = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(seller_id), "role": "seller"})
            if not seller:
                return Response({'error': 'Seller not found.'}, status=status.HTTP_404_NOT_FOUND)
            user_data = {
                'status': status_value,
                
            }
            if status_value:
                update_result = Database.Update(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(seller_id)}, user_data)
                if update_result.matched_count == 0:
                    return Response({'error': 'Product update failed.'}, status=status.HTTP_404_NOT_FOUND)
                # Send approval email to the seller
                subject = f"Your account has been {status_value}!"
                message = f"Hello {seller.get('first_name', 'User')},\n\nYour account has been {status_value} by the admin. You can now log in to your account.\n\nBest regards,\nThe Team"
                from_email = settings.EMAIL_HOST_USER  
                recipient_list = [seller['email']]

                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False
                )

                return Response({
                    'status': status.HTTP_200_OK,
                    'message': f'Seller account {status_value} and email sent.'
                }, status=status.HTTP_200_OK)

            else:
                return Response({
                    'status': status.HTTP_200_OK,
                    'message': 'Seller Unavailable and try after some time.'
                }, status=status.HTTP_200_OK)

        except Exception as e:
            print(str(e), "error")
            return Response({
                'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        db_handle, _ = get_db_handle()
        user_collection = db_handle.user_collection
        reset_token_collection = db_handle.reset_token_collection

        # Find the user by email
        user = user_collection.find_one({"email": email.lower()})

        if not user:
            return Response({'error': 'No user found with this email.'}, status=status.HTTP_404_NOT_FOUND)
        token = uuid.uuid4().hex
        expiry_time = datetime.now(timezone.utc) + timedelta(hours=1)

        # Store token and expiry in the database
        reset_token_collection.update_one(
            {"user_id": user['_id']},
            {"$set": {"token": token, "expiry": expiry_time}},
            upsert=True
        )
        # Construct reset URL
        reset_url = f"{os.getenv("FRONTEND_URL")}/api/reset-password?token={token}"
        
        send_mail(
            'Password Reset Link',
            f'Use the following link to reset your password: {reset_url}',
            os.getenv("EMAIL_HOST_USER")
            [email],
            fail_silently=False
        )
        return Response({'message': 'Password reset link sent successfully.','reset_url':reset_url}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            db_handle, _ = get_db_handle()  # Get the MongoDB database handle
            user_collection = db_handle.user_collection
            reset_token_collection = db_handle.reset_token_collection

            # Check if the token is valid and not expired
            token_record = reset_token_collection.find_one({"token": token})
            if not token_record or token_record['expiry'] < datetime.now():
                return Response({'message': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

            # Find the user associated with the token
            user = user_collection.find_one({"_id": token_record['user_id']})
            if not user:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Update the user's password
            user_collection.update_one({"_id": user['_id']}, {"$set": {"password": hashed_password}})

            # Remove the token after successful password reset
            reset_token_collection.delete_one({"token": token})

            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#decode token 
def decode_token(request):

    token = request.headers.get('Authorization', None)
    
    if token is None:
        print("Token not provided")
        return False
        # return Response({'error': 'Token not provided.'}, status=status.HTTP_400_BAD_REQUEST)
    token = token.split(' ')[1] if token.startswith('token ') else token
    try:
        # Decode the JWT token
        decoded_token = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=["HS256"])  # Use your JWT secret key
        seller_id = decoded_token.get('user_id')
        
        if not seller_id:
            return  False
        return seller_id 
    except Exception as e:
        return False
    except jwt.DecodeError:
        return False


class AddCategoryView(APIView):
    def post(self, request):
        getadminID = decode_token(request)
        if not getadminID:
            return Response({'error': 'Please Login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
        try:
            adminID = ObjectId(getadminID)
        except Exception as e:
            return Response({'error': 'Invalid token ID format.'}, status=status.HTTP_400_BAD_REQUEST)
        db_handle, _ = get_db_handle()
        user_data = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": adminID})
        if not user_data or user_data['role'] != 'admin':
            return Response({'error': 'You are not authorized to add categories. Admin access required.'}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        title = data.get('title')
        short_description = data.get('short_description')
        product_type = data.get('product_type')

        images = request.FILES.getlist('image')
        if not images:
            return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if not title or not short_description or not product_type:
            return Response({'error': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            existing_category = Database.FindOne(db_handle, Database.CATEGORY_COLLECTION, {"product_type": product_type})
            if existing_category:
                return Response({'error': f'Product type "{product_type}" already exists. Please choose a different product type.'}, status=status.HTTP_400_BAD_REQUEST)
            # Set up the base URL (protocol and host) for the image URL
            protocol = "https" if request.is_secure() else "http"
            host = request.get_host()

            image_dir = os.path.join(settings.MEDIA_ROOT, 'category_images')
            if not os.path.exists(image_dir):
                os.makedirs(image_dir)
            image_urls = []
            for image in images:
                image_name = f"{title.replace(' ', '_')}_{datetime.utcnow().timestamp()}_{Path(image.name).suffix}" 
                image_path = os.path.join(image_dir, image_name)
                with open(image_path, 'wb') as f:
                    for chunk in image.chunks():
                        f.write(chunk)

                # Generate the image URL
                image_url = f"{protocol}://{host}/media/category_images/{image_name}"
                image_urls.append(image_url)

            # Prepare category data
            db_handle, _ = get_db_handle()

            category = {
                "title": title,
                "image": image_urls,  # Store the list of image URLs
                "short_description": short_description,
                "status": 'active',
                "admin_id": getadminID,
                "product_type": product_type,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }

            # Insert the category into the database
            inserted_id = Database.InsertData(db_handle, Database.CATEGORY_COLLECTION, category)
            category['_id'] = str(inserted_id)
            category=convert_objectid_to_str(category)
            return Response({
                "status": status.HTTP_201_CREATED,
                "message": "Category added successfully.",
                "data": category
            }, status=status.HTTP_201_CREATED)
        # Catch JWT token expiry error
        except Exception as e:
            return Response({'error': 'Token has expired. Please login again.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Catch JWT decoding error (Invalid token)
        except jwt.DecodeError:
            return Response({'error': 'Invalid token. Please provide a valid token.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Catch any other exceptions related to the database insert
        except Exception as e:
            return Response({'error': f'Error inserting data into category_collection: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from bson import ObjectId
def convert_objectid_to_str(obj):
    if isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)  # Convert ObjectId to string
    else:
        return obj

#get categories by product type in admin section
class GetCategoriesByProductType(APIView):

    def post(self, request):

        # Decode token to get the seller ID
        getsellerID = decode_token(request)
        
        # If the seller ID is not found, return an error
        if not getsellerID:
            return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Fetch the seller's categories
            db_handle, _ = get_db_handle()
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {"admin_id": getsellerID})
            
            # If no categories are found for the seller
            if not categories:
                return Response({'error': 'No categories found for this seller.'}, status=status.HTTP_404_NOT_FOUND)
            
            # Initialize response data structure
            product_data = {
                "bracelets": [],
                "earrings": [],
                "ring": [],
                "necklaces": [],
            }
            
            # Process each category
            for category in categories:
                if isinstance(category, dict):
                    category = convert_objectid_to_str(category) 
                    
                    category_product_type = category.get("product_type", "").strip().lower()
                    if category_product_type in product_data:
                        print(f"Adding category {category['title']} to product type {category_product_type}") 
                        product_data[category_product_type].append({
                            'title': category.get('title', ''),
                            'short_description': category.get('short_description', ''),
                            'image': category.get('image', ''),
                            'product_type': category.get('product_type', ''),
                            'created_at': category.get('created_at', ''),
                            'updated_at': category.get('updated_at', ''),
                            'status': category.get('status', ''),
                            })
            
            response_data = {
                "bracelets": product_data.get("bracelets", []),
                "earrings": product_data.get("earrings", []),
                "rings": product_data.get("ring", []),
                "necklaces": product_data.get("necklaces", [])
            }
            
            # Return the formatted response
            return Response({
                'status': status.HTTP_200_OK,
                'message': 'Product categories fetched successfully',
                'data': response_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle unexpected errors
            return Response({'error': f'Error fetching categories: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Get a category in seller section
class GetCategorySeller(APIView):
    def post(self,request):
        
        seller_id = decode_token(request)
        if not seller_id:
            return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
        category_list = []
        db_handle, _ = get_db_handle()
        try:
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {})
            for category in categories:
                category_data = {
                    "title": category.get("title", ""),
                    "category_name": category.get("product_type", ""),
                    "category_id": str(category.get("_id", "")), 
                }
                category_list.append(category_data)
            return Response({"status": status.HTTP_200_OK, "message": "Categories fetched successfully", "data": category_list}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'Error fetching categories: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#Add Product
class AddProductView(APIView):
    def post(self, request):
        try:
            # Decode token to get the seller ID
            getsellerID = decode_token(request)
            print(getsellerID)
            # If the seller ID is not found, return an error
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            db_handle, _ = get_db_handle()
            user_data = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(getsellerID)})
            
            if not user_data:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
            admin_id = None
            user_role = user_data['role']
            if user_role == 'admin':
                product_status = 'admin'
                admin_id = getsellerID
            elif user_role == 'seller':
                product_status = "pending"
                admin_id = None
            else:
                return Response({'error': 'User role is not valid.'}, status=status.HTTP_403_FORBIDDEN)
            data = request.data
            name = data.get('name')
            featured_image = data.get('featured_image')
            short_description = data.get('short_description')
            price = data.get('price')
            discount_percentage = data.get('discount_percentage')
            discount_price = data.get('discount_price')
            tag_string = data.get('tag', '')
            sizes = data.get('sizes')
            colors = data.get('colors')
            gallery_images = request.FILES.getlist('gallery_images')
            category_id = data.get('category_id')
            category_ids = ObjectId(category_id)
            sku = 'null'
            if not gallery_images:
                return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if not name or not featured_image or not short_description or not price or not discount_percentage or not discount_price or not tag_string or not sizes or not colors:
                return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)
            
            tags = tag_string.split(',') 
            size = sizes.split(',') 
            color = colors.split(',') 
            db_handle, _ = get_db_handle()
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {"_id": category_ids})
            # If no categories are found for the seller
            if not categories:
                return Response({'error': 'No categories found for this seller.'}, status=status.HTTP_404_NOT_FOUND)
            
            # category_ids = [category['_id'] for category in categories]
            protocol = "https" if request.is_secure() else "http"
            host = request.get_host()
            featured_image_dir  = os.path.join(settings.MEDIA_ROOT, 'featured_image')
            gallery_image_dir  = os.path.join(settings.MEDIA_ROOT, 'gallery_images')
            os.makedirs(featured_image_dir, exist_ok=True)
            os.makedirs(gallery_image_dir, exist_ok=True)
            featured_image_name = f"{name.replace(' ', '_')}_featured_{datetime.utcnow().timestamp()}{Path(featured_image.name).suffix}"
            featured_image_path = os.path.join(featured_image_dir, featured_image_name)
            with open(featured_image_path, 'wb') as f:
                for chunk in featured_image.chunks():
                    f.write(chunk)

            featured_image_url = f"{protocol}://{host}/media/featured_image/{featured_image_name}"

            gallery_image_urls = []
            for image in gallery_images:
                image_name = f"{name.replace(' ', '_')}_gallery_{datetime.utcnow().timestamp()}_{Path(image.name).suffix}"
                image_path = os.path.join(gallery_image_dir, image_name)
                with open(image_path, 'wb') as f:
                    for chunk in image.chunks():
                        f.write(chunk)

                # Generate the image URL
                gallery_image_url = f"{protocol}://{host}/media/gallery_images/{image_name}"
                gallery_image_urls.append(gallery_image_url)
            sku = f"SKU-{datetime.utcnow().timestamp()}"
            product = {
                "name": name,
                "featured_image": featured_image_url,
                "short_description": short_description,
                "price":price,
                "discount_percentage":discount_percentage,
                "discount_price":discount_price,
                "tag":tags,
                "sizes":size,
                "colors":color,
                "gallery_images": gallery_image_urls,
                "sku": sku,
                "status": product_status,
                "sellert_id": getsellerID,
                "admin_id":admin_id,
                "category_id": category_id,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            inserted_id = Database.InsertData(db_handle, Database.PRODUCT_COLLECTION, product)
            product['_id'] = str(inserted_id)
            if product_status == "pending":
                seller_email = user_data['email']
                seller_name = user_data.get('first_name', 'Seller')

                subject = "Your product is waiting for admin approval!"
                message = f"""
                Hello {seller_name},

                Your product "{name}" has been successfully added, and it is now awaiting approval from the admin.

                You will receive a notification once your product is approved or rejected.

                Best regards,
                The Team
                """
                from_email = settings.EMAIL_HOST_USER  # Assuming EMAIL_HOST_USER is configured in settings.py
                recipient_list = [seller_email]

                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False
                )
            return Response({"status": status.HTTP_201_CREATED,'message': 'Product added successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            # Handle unexpected errors
            return Response({'error': f'Error adding product: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
#seller list
class GetUserListAPIView(APIView):
    def post(self, request):
        try:
            getsellerID = decode_token(request)
            print(getsellerID)
            # If the seller ID is not found, return an error
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            db_handle, _ = get_db_handle()
            user_data = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(getsellerID)})
            print(user_data,'user data +--------')
            if not user_data:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
            user_role = user_data['role']
            if user_role == 'admin':
                sellers = Database.FindAll(db_handle, Database.USER_COLLECTION, {"role":"seller"})
            elif user_role == 'seller':
                sellers = [user_data]
            else:
                return Response(
                    {'error': 'Invalid role. Access denied.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            processed_list = []
            print("sellers-------------",sellers)
            for seller in sellers:
                print('seller-->>>',seller)
                print("Trueeeee", isinstance(seller, dict))
                if isinstance(seller, dict):

                    seller['_id'] = str(seller.get('_id'))
                    processed_list.append(seller)
            return Response({
                "status": status.HTTP_200_OK,
                "message": "Users fetched successfully.",
                "data": processed_list
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Error fetching products: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#Get product list admin and seller
class GetAllProductListAPIView(APIView):
    def post(self,request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            db_handle, _ = get_db_handle()
            userdetails = Database.FindAll(db_handle, Database.USER_COLLECTION,{"_id":ObjectId(getsellerID)})
            if userdetails[0]['role'].lower()=="seller":
                getProduct = Database.FindAll(db_handle, Database.PRODUCT_COLLECTION, {"sellert_id": getsellerID})
            elif userdetails[0]['role'].lower()=="admin":
                getProduct = Database.FindAll(db_handle, Database.PRODUCT_COLLECTION,{})
                
            if getProduct:
                for product in getProduct:
                    product['_id'] = str(product['_id'])
                return Response({"status": "success", "products": getProduct}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No products found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error retrieving product list: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Edit category
class EditCategoryAPIView(APIView):
    def put(self, request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

            category_id = request.data.get("category_id")
            if not category_id:
                return Response({'error': 'Category ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

            db_handle, _ = get_db_handle()

            category = Database.FindOne(db_handle, Database.CATEGORY_COLLECTION, {"_id": ObjectId(category_id)})
            if not category:
                return Response({'error': 'Category not found.'}, status=status.HTTP_404_NOT_FOUND)
            title = request.data.get('title', category['title'])
            short_description = request.data.get('short_description', category['short_description'])
            product_type = request.data.get('product_type', category['product_type'])
            uploaded_images = request.FILES.getlist('image')
            existing_images = category.get('image', [])
            image_urls = []

            if uploaded_images:
                protocol = "https" if request.is_secure() else "http"
                host = request.get_host()
                image_dir = os.path.join(settings.MEDIA_ROOT, 'category_images')

                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)
                for image in uploaded_images:
                    image_name = f"{title.replace(' ', '_')}_{datetime.utcnow().timestamp()}_{Path(image.name).suffix}"
                    image_path = os.path.join(image_dir, image_name)
                    with open(image_path, 'wb') as f:
                        for chunk in image.chunks():
                            f.write(chunk)

                    # Generate the image URL
                    image_url = f"{protocol}://{host}/media/category_images/{image_name}"
                    image_urls.append(image_url)
            else:
                # If no new images are uploaded, use the existing images
                image_urls = existing_images
            if not title or not short_description or not product_type:
                return Response({'error': 'Title, short description, and product type are required.'}, status=status.HTTP_400_BAD_REQUEST)

            # Step 6: Prepare the data to update the category
            update_data = {
                "title": title,
                "short_description": short_description,
                "product_type": product_type,
                "image": image_urls,  
                "updated_at": datetime.utcnow().isoformat()  # Set the updated timestamp
            }

            update_result = Database.Update(db_handle, Database.CATEGORY_COLLECTION, {"_id": ObjectId(category_id)}, update_data)
            if update_result.matched_count == 0:
                return Response({'error': 'Failed to update category.'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'status': 'Category updated successfully!',
                'category_id': category_id,
                'updated_data': update_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': f'Error updating category: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EditProductAPIView(APIView):
    def put(self, request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

            product_id = request.data.get("product_id")
            if not product_id:
                return Response({'error': 'Product ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

            db_handle, _ = get_db_handle()
            
            product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
            user_role = product['status']
            if user_role not in ['admin', 'seller']:
                return Response({'error': 'Role is not valid.'}, status=status.HTTP_403_FORBIDDEN)
            # if user_role == 'seller' and product.get('seller_id') != getsellerID:
            #     return Response({'error': 'You can only update your own products.'}, status=status.HTTP_403_FORBIDDEN)
            name = request.data.get('name', product['name'])
            featured_image = request.data.get('featured_image', product['featured_image'])
            short_description = request.data.get('short_description', product['short_description'])
            discount_price = request.data.get('discount_price', product['discount_price'])
            discount_percentage = request.data.get('discount_percentage', product['discount_percentage'])
            price = request.data.get('price', product['price'])
            tag_string = request.data.get('tag', product['tag'])
            sizes = request.data.get('sizes', product['sizes'])
            colors = request.data.get('colors', product['colors'])
            gallery_images = request.FILES.getlist('gallery_images')
            if not product:
                return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)
            if not gallery_images and not product.get('gallery_images'):
                return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)
            protocol = "https" if request.is_secure() else "http"
            host = request.get_host()
            if featured_image:
                featured_image_name = f"{uuid.uuid4().hex}_{featured_image.name}"
                featured_image_path = os.path.join(settings.MEDIA_ROOT, 'featured_image', featured_image_name)
                with open(featured_image_path, 'wb') as f:
                    for chunk in featured_image.chunks():
                        f.write(chunk)
                featured_image_url = f"{protocol}://{host}/media/gallery_images/{featured_image_name}"
            gallery_image_paths =[]
            for gallery_image in gallery_images:
                gallery_image_name = f"{uuid.uuid4().hex}_{gallery_image.name}"
                gallery_image_path = os.path.join(settings.MEDIA_ROOT, 'gallery_images', gallery_image_name)
                with open(gallery_image_path, 'wb') as f:
                    for chunk in gallery_image.chunks():
                        f.write(chunk)
                image_url = f"{protocol}://{host}/media/gallery_images/{gallery_image_name}"
                gallery_image_paths.append(image_url)
            tags = tag_string.split(',') 
            size = sizes.split(',') 
            color = colors.split(',')
            updated_product_data = {
                'name': name,
                'featured_image': featured_image_url,
                'short_description': short_description,
                'discount_price': discount_price,
                'discount_percentage': discount_percentage,
                'price': price,
                'tag': tags,
                'sizes': size,
                'colors': color,
                'gallery_images': gallery_image_paths,
                'updated_at': datetime.utcnow().isoformat()  # Set the updated timestamp
            }
            update_result = Database.Update(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)}, updated_product_data)
            print(update_result,'???????')
            if update_result.matched_count == 0:
                return Response({'error': 'Failed to update product.'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'status': 'Category updated successfully!',
                'category_id': product_id,
                'updated_data': updated_product_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print(e)
            return Response({'error': 'An error occurred while updating the product.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteProductAPIView(APIView):
    def delete(self,request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            product_id = request.data.get('product_id')
            db_handle, _ = get_db_handle()
            product = Database.FindOne(db_handle,Database.PRODUCT_COLLECTION,{"_id":ObjectId(product_id)})
            if not product:
                return Response({"status":status.HTTP_200_OK,"message":"Product not found."})
            user_role = product['status']
            if user_role == 'admin':
                delete_result = Database.Delete(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
                if delete_result and delete_result.deleted_count > 0:
                    return Response({"status": status.HTTP_200_OK, "message": "Product deleted successfully."})
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Failed to delete product."})
            elif user_role == 'seller' and product.get('seller_id') == getsellerID:
                # Only the seller who created the product can delete it
                delete_result = Database.Delete(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
                if delete_result and delete_result.deleted_count > 0:
                    return Response({"status": status.HTTP_200_OK, "message": "Product deleted successfully."})
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Failed to delete product."})
            else:
                return Response({"status": status.HTTP_403_FORBIDDEN, "message": "You are not authorized to delete this product."})
        except Exception as e:
            print(e)
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message":"An error occurred while deleting the product."})


class AdminApproveProduct(APIView):
    def post(self, request):
        try:
            # Decode token to get the admin's ID
            gettokenID = decode_token(request)
            if not gettokenID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

            # Get product and status details from request
            product_id = request.data.get('product_id')
            status_value = request.data.get('status')
            if status_value.lower() not in ['approve', 'decline']:
                return Response({'error': 'Invalid status. It should be either "approve" or "decline".'}, status=status.HTTP_400_BAD_REQUEST)
            status_value = status_value.title()
            db_handle, _ = get_db_handle()
            product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
            user_id = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(product['sellert_id'])})
            print(user_id['email'],'user_id')
            if not product:
                return Response({'error': 'Product not found for the given seller ID.'}, status=status.HTTP_404_NOT_FOUND)
            product_data = {
                'status': status_value,
                
            }
            if status_value:
                update_result = Database.Update(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product['_id'])},product_data)
                if update_result.matched_count == 0:
                    return Response({'error': 'Product update failed.'}, status=status.HTTP_404_NOT_FOUND)

                # Send approval email to the seller
                seller = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"sellert_id": product['sellert_id']})
                if seller:
                    subject = f"Your product has been {status_value}!"
                    message = f"""
                    Hello {seller.get('first_name', 'User')},

                    Your product "{product['name']}" has been successfully {status_value} by the admin.

                    Best regards,
                    The Team
                    """
                    from_email = settings.EMAIL_HOST_USER
                    recipient_list = [user_id['email']]

                    send_mail(
                        subject,
                        message,
                        from_email,
                        recipient_list,
                        fail_silently=False
                    )

                return Response({
                    'status': status.HTTP_200_OK,
                    'message': f'Product {status_value} and email sent to seller.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': status.HTTP_200_OK,
                    'message': 'Product Unavailable and try after some time.'
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class AddToCartAPIView(APIView):
    def post(self, request):
        """
        Add a product to the user's cart.
        """
        user_id = request.data.get("user_id")
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)  # Default quantity is 1

        # Validate inputs
        if not user_id or not product_id:
            return Response({"error": "User ID and Product ID are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Check if the product exists in the 'products' collection
            db_handle, _ = get_db_handle()
            product=Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
            print('prodict---->>',product)
            print('type prodict---->>',type(product))
            if not product:
                return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)

            # Check if the product is already in the cart
            # cart_item = Database.ADD_TO_CART_COLLECTION.find_one({"user_id": user_id, "product_id": product_id})
            cart_item = Database.FindOne(db_handle, Database.ADD_TO_CART_COLLECTION, {"user_id": user_id, "product_id": product_id})
            if cart_item:
                # Update quantity if the product is already in the cart
                Database.Update(db_handle, Database.ADD_TO_CART_COLLECTION,{"user_id": user_id, "product_id": product_id},{"$inc": {"quantity": quantity}})
            else:
                # Add a new product to the cart
                Database.InsertData(
                    db_handle, Database.ADD_TO_CART_COLLECTION,
                    {
                    "user_id": user_id,
                    "product_id": product_id,
                    "quantity": quantity,
                    "added_date": datetime.utcnow()
                    }
)

            return Response({"message": "Product added to cart successfully."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class RemoveFromCartAPIView(APIView):
    def post(self, request):
        """
        Remove a product from the user's cart.
        """
        user_id = request.data.get("user_id")
        product_id = request.data.get("product_id")

        # Validate inputs
        if not user_id or not product_id:
            return Response({"error": "User ID and Product ID are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Convert product_id to ObjectId
            try:
                product_id = ObjectId(product_id)
            except Exception:
                return Response({"error": "Invalid Product ID format."}, status=status.HTTP_400_BAD_REQUEST)

            # Get the database handle
            db_handle, _ = get_db_handle()

            # Check if the product exists in the cart
            cart_item = Database.FindOne(
                db_handle,
                Database.ADD_TO_CART_COLLECTION,
                {"user_id": user_id, "product_id": str(product_id)}  # Use product_id as string in cart
            )

            if not cart_item:
                return Response({"error": "Product not found in the cart."}, status=status.HTTP_404_NOT_FOUND)

            # Remove the product from the cart
            Database.Delete(
                db_handle,
                Database.ADD_TO_CART_COLLECTION,
                {"user_id": user_id, "product_id": str(product_id)}
            )

            return Response({"message": "Product removed from cart successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            # Log the error for debugging purposes
            print(f"Error in RemoveFromCart API: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class ApprovedProductsAPIView(APIView):
    def post(self, request):
        """
        Fetch all products approved by the admin and group them by product type (category name).
        """
        try:
            db_handle, _ = get_db_handle()

            # Fetch all approved products (with status 'approve')
            approved_products = Database.FindAll(
                db_handle,
                Database.PRODUCT_COLLECTION,
               {"status": {"$in": ["approve", "admin"]}}  # The query is used to filter products with "approve" status
            )

            # Fetch all categories
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {})  # Empty query to get all categories

            if not approved_products:
                print("No approved products found in the database.")
                return Response({
                    "status": status.HTTP_404_NOT_FOUND,
                    "message": "No approved products found."
                }, status=status.HTTP_404_NOT_FOUND)

            # Create a mapping of category_id to category name
            category_mapping = {str(category["_id"]): category["product_type"] for category in categories}

            # Initialize a dictionary to group products by product type (category name)
            categorized_products = {}

            # Loop through approved products
            for product in approved_products:
                # Get the category_id and map it to the category name
                category_id = product.get("category_id", "").strip()
                product_type = category_mapping.get(category_id, "Unknown Category")

                # Ensure product type exists in categorized_products
                if product_type not in categorized_products:
                    categorized_products[product_type] = []

                # Add the product details to the appropriate product type
                categorized_products[product_type].append({
                    "id": str(product.get("_id", "")),  # Convert ObjectId to string
                    "title": product.get("name", ""),
                    "short_description": product.get("short_description", ""),
                    "price": product.get("price", "0"),
                    "discount_percentage":product.get("discount_percentage"),
                    "discount_price": product.get("discount_price", "0"),
                    "product_type": product_type,  # Add product type (category name)
                    "featured_image": product.get("featured_image", ""),
                    "tag":product.get("tag"),
                    "gallery_images":product.get("gallery_images"),
                    "created_at": product.get("created_at", ""),
                    "updated_at": product.get("updated_at", ""),
                    "status": product.get("status", "")
                })

            # Debugging: Print the final categorized products
            print("Categorized Products:", categorized_products)

            # Return the response with categorized products
            return Response({
                "status": status.HTTP_200_OK,
                "message": "Fetched successfully.",
                "products": categorized_products
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Log the error for debugging
            print(f"Error in ApprovedProducts API: {e}")
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": "An error occurred while fetching approved products.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





import stripe
stripe.api_key = "sk_test_51Qez1qGhEzHZ6hIbCqEYvKkGMeXWR30BpGLYxgyqPPifMMgQiswU3nazRQrgv4uBINyb5KozOSyWycUATSGgJu2600gtFV8B5R"

class CheckoutSessionView(APIView):
    def post(self, request):
        """
        Creates a Stripe payment session for the user based on the items in the cart.
        This view does not require frontend interaction.
        """
        # Fetch product_id and quantity from the request
        getcustomerID = decode_token(request)  # Implement this function to decode the token
        print("Decoded Customer ID:", getcustomerID) 
        customer_id = request.data.get("customer_id", getcustomerID)
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)
        if quantity:
            quantity=int(quantity)
        # Validate the inputs
        if not product_id:
            return Response({"error": "Product ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(quantity, int) or quantity <= 0:
            return Response({"error": "Quantity must be a positive integer."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Fetch the product from the database
        db_handle, _ = get_db_handle()
        product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
        print("product---->>>",product)
        if not product:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)
        seller_id = product.get("sellert_id","")
        
        # Calculate the total price and prepare line items
        price = int(product.get("price", 0))  # Assume price is stored in the product collection
        print("price-----",type(price))
        if not price:
            return Response({"error": "Product price is missing or invalid."}, status=status.HTTP_400_BAD_REQUEST)

        total_amount = price * quantity  
        line_items = [
            {
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': product.get("name", "Unknown Product"),
                    },
                    'unit_amount': int(price )*100,  
                },
                'quantity': quantity,
            }
        ]
        print("dgfh____>>>>",line_items)
        
        # Create a payment session on Stripe
        try:
            # Optionally, store the order in the database (MongoDB)
            order_data = {
                "product_id": product_id,
                "quantity": quantity,
                "customer_id":customer_id,
                "seller_id":seller_id,
                "total_amount": total_amount,
                # "stripe_session_id": session.id,
                "status": "pending",
                "created_at": datetime.utcnow()
            }
            order_id = Database.InsertData(db_handle, Database.ORDER_COLLECTION, order_data)
            print('order-id--->>',order_id)
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=line_items,
                mode='payment',
                success_url=f'http://localhost:3000/payment-success?order_id={order_id}',  # URL for successful payment
                cancel_url=f'http://localhost:3000/payment-cancel/',    # URL for canceled payment
            )

            # update the  databse
            session_data={
                    "stripe_session_id": session.id,
            }
            updt=Database.Update(db_handle,Database.ORDER_COLLECTION,{"_id": ObjectId(order_id)}, session_data)

            
            return Response({"session_id": session.id,"customer_id":customer_id,"session_url": session.url, "order_id": str(order_id)}, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class PaymentSuccessAPIView(APIView):
    def post(self, request):
        try:
            db_handle, _ = get_db_handle()

            # Extract data from the request
            order_id = request.data.get("order_id")
            print('order_id---->>>',order_id)
            # Validate required fields
            if not order_id:
                return Response({
                    "message": "order_id are required field."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prepare the combined data for insertion
            order_and_payment_data = {
                "status": "Paid",  
                # "payment_method": "Card", 
                "new": True, 
            }

            print("Combined Order and Payment Data:", order_and_payment_data)

            # Insert the combined data into the database
            order_detail = Database.Update(db_handle, Database.ORDER_COLLECTION,  {"_id": ObjectId(order_id)}, order_and_payment_data)

            return Response({
                "message": "Order and payment details stored successfully.",
                "order_detail": str(order_detail)
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "message": "An error occurred while storing order and payment details.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class SellerOrderApiView(APIView):
    def post(self, request):
        try:
            db_handle, _ = get_db_handle()

            # Query to fetch new orders
            query = {"new": True}
            print("Executing query:", query)

            # Fetch new orders
            orders = list(db_handle[Database.PAYMENT_SUCCESS_COLLECTION].find(query))

            # If no orders are found, return early
            if not orders:
                return Response({
                    "message": "No new orders found.",
                    "data": []
                }, status=status.HTTP_200_OK)

            result = []
            seen_order_ids = set()
            for order in orders:
                if order["order_id"] in seen_order_ids:
                    continue
                seen_order_ids.add(order["order_id"])

                product_detail = {}
                customer_detail = {}

                # Fetch product details
                product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(order["product_id"])})
                if product:
                    product_detail = {
                        "product_name": product.get("name"),
                        "product_price": product.get("price"),
                        "product_description": product.get("description"),
                    }

                # Validate and fetch customer details
                customer_id = order["customer_id"]
                if customer_id:
                    try:
                        customer = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(order['customer_id'])})
                        if customer:
                            customer_detail = {
                                "customer_name": customer.get("first_name"),
                                "customer_email": customer.get("email"),
                                "customer_phone": customer.get("phone_number"),
                            }
                        else:
                            print(f"No customer found with ID: {customer_id}")
                    except Exception as e:
                        print(f"Error fetching customer with ID {customer_id}: {e}")
                else:
                    print(f"Skipping order {order['_id']} due to missing customer_id")

                # Add details to the order
                order["_id"] = str(order["_id"])
                order["product_details"] = product_detail
                order["customer_details"] = customer_detail

                # Append the enriched order to the result list
                result.append(order)

            print("Final result:", result)  # Debugging: Log the final result

            return Response({
                "message": "New orders retrieved successfully.",
                "data": result
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error occurred: {str(e)}")  # Debugging: Log exceptions
            return Response({
                "message": "An error occurred while fetching seller orders.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class OrderTrackingAPIView(APIView):
    def post(self, request):
        try:
            db_handle, _ = get_db_handle()

            # Get `order_id` from the query params
            order_id = request.data.get("order_id")
            print("order_id------",order_id)
            if not order_id:
                return Response({
                    "message": "Order ID is required to track an order."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Find the order in the database using `order_id`
            order = db_handle[Database.PAYMENT_SUCCESS_COLLECTION].find_one({"order_id": order_id})

            if not order:
                return Response({
                    "message": f"No order found with order_id: {order_id}"
                }, status=status.HTTP_404_NOT_FOUND)

            # Fetch additional product details
            product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(order["product_id"])})
            product_details = {
                "product_name": product.get("name"),
                "product_price": product.get("price"),
                "short_description": product.get("short_description"),
            } if product else {}

            # Prepare the response with order tracking information
            order_tracking_details = {
                "order_id": order.get("order_id"),
                "customer_id": order.get("customer_id"),
                "product_id": order.get("product_id"),
                "price": order.get("price"),
                "quantity": order.get("quantity"),
                "currency": order.get("currency"),
                "delivery_status": order.get("delivery_status"),
                "payment_status": order.get("payment_status"),
                "created_at": order.get("created_at"),
                "product_details": product_details,
            }

            return Response({
                "message": "Order tracking details retrieved successfully.",
                "data": order_tracking_details
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error occurred: {str(e)}")  # Debugging: Log exceptions
            return Response({
                "message": "An error occurred while fetching order tracking details.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






class AddressFetchAPIView(APIView):
    def post(self, request):
        """
        Fetch the address field for a user from the `user_collection`.
        """
        try:
            # Decode the user ID from the token
            getuserID = decode_token(request)  # Implement this function to decode the token
            print("Decoded Customer ID:", getuserID)
            user_id = request.data.get("customer_id", getuserID)

            if not user_id:
                return Response({"error": "Invalid or missing customer_id."}, status=status.HTTP_400_BAD_REQUEST)

            # Get the database handle
            db_handle, _ = get_db_handle()

            # Fetch the user document from the collection
            user = Database.FindOne(db_handle,Database.USER_COLLECTION,{"_id": ObjectId(user_id)})

            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            # Extract the address array (default to an empty array if not present)
            address_list = user.get("address", [])

            return Response({"address": address_list}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self, request):
        """
        Update the address field for a user in the `user_collection`.
        """
        getuserID = decode_token(request)  # Implement this function to decode the token
        print("Decoded Customer ID:", getuserID)
        user_id = request.data.get("customer_id", getuserID)
        new_address = request.data.get("address")

        # Validate the inputs
        if not user_id:
            return Response({"error": "Invalid or missing customer_id."}, status=status.HTTP_400_BAD_REQUEST)

        # if not new_address or not isinstance(new_address, dict):
        #     return Response({
        #         "error": "Invalid or missing address. Address must be an object with fields: street, city, state, country, zip_code."
        #     }, status=status.HTTP_400_BAD_REQUEST)

        # Validate the structure of the address object
        required_fields = ["street", "city", "state", "country", "zip_code"]
        missing_fields = [field for field in required_fields if field not in new_address]

        if missing_fields:
            return Response({
                "error": f"Missing fields in address: {', '.join(missing_fields)}."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the database handle
            db_handle, _ = get_db_handle()

            # Check if the user exists
            user = Database.FindOne(
                db_handle,
                Database.USER_COLLECTION,
                {"_id": ObjectId(user_id)}
            )

            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            # Update the address field without replacing the whole document
            update_result = Database.Update(db_handle,Database.USER_COLLECTION,{"_id": ObjectId(user_id)}, {"address":new_address})
            if update_result.modified_count == 0:
                return Response({
                    "error": "Address update failed. No changes detected or user not found."
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "Address updated successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class AccountdetailsAPIview(APIView):
    def post(self,request):
        try:
            getuserID = decode_token(request)  # Implement this function to decode the token
            print("Decoded Customer ID:", getuserID)
            user_id = request.data.get("customer_id", getuserID)

            if not user_id:
                return Response({"error": "Invalid or missing customer_id."}, status=status.HTTP_400_BAD_REQUEST)
            db_handle, _ = get_db_handle()
            user = Database.FindOne(db_handle,Database.USER_COLLECTION,{"_id": ObjectId(user_id)})

            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            
            username_list = user.get("username", [])
            firstname_list = user.get("first_name", [])
            lastname_list = user.get("last_name", [])
            email_list = user.get("email", [])
            phonenumber_list = user.get("phone_number", [])

            return Response({"username": username_list,"first_name": firstname_list,"last_name": lastname_list,"email": email_list,"phone_number": phonenumber_list}, status=status.HTTP_200_OK)
        

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def put(self, request):
        """
        Update the address field for a user in the `user_collection`.
        """
        getuserID = decode_token(request)  # Implement this function to decode the token
        print("Decoded Customer ID:", getuserID)
        user_id = request.data.get("customer_id", getuserID)
        new_username = request.data.get("username")
        new_first_name = request.data.get("first_name")
        new_last_name = request.data.get("last_name")
        new_email = request.data.get("email")
        new_phone_number = request.data.get("phone_number")

        # Validate the inputs
        if not user_id:
            return Response({"error": "Invalid or missing customer_id."}, status=status.HTTP_400_BAD_REQUEST)
        

        try:
            # Get the database handle
            db_handle, _ = get_db_handle()

            # Check if the user exists
            user = Database.FindOne(
                db_handle,
                Database.USER_COLLECTION,
                {"_id": ObjectId(user_id)}
            )

            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            
            if new_email:
                email_exists = Database.FindOne(
                    db_handle,
                    Database.USER_COLLECTION,
                    {"email": new_email, "_id": {"$ne": ObjectId(user_id)}}  # Exclude the current user
                )
                if email_exists:
                    return Response(
                        {"error": "The email address is already in use by another account."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            # Update the address field without replacing the whole document
            update_result = Database.Update(db_handle,Database.USER_COLLECTION,{"_id": ObjectId(user_id)}, {"username":new_username,"first_name":new_first_name,"last_name":new_last_name,"email":new_email,"phone_number":new_phone_number})
            if update_result.modified_count == 0:
                return Response({
                    "error": "All update failed. No changes detected or user not found."
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "All fields updated successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)