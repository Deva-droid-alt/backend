from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND,HTTP_201_CREATED,HTTP_500_INTERNAL_SERVER_ERROR,HTTP_403_FORBIDDEN
from . import models
from datetime import date
from django.shortcuts import get_object_or_404
from django.conf import settings
from . import serializer
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from rest_framework.authtoken.models import Token
from .permissions import IsManager, IsEmployee, IsAdmin
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import send_mail
from .serializer import EmployeeSerializer,ManagerSerializer,RequestSerializerAdmin,RequestSerializerEmployee,RequestSerializerManager,NewTravelSerializer,TravelSerializer
from django.views.decorators.csrf import csrf_exempt
from django.db import IntegrityError
from . import models

import logging 
logger =logging.getLogger(__name__)

@api_view(["GET","POST"])
@csrf_exempt
def admin_creation(request):
    '''
    Function to create an admin.
    '''
    try:
        if request.method == 'POST':
            required_fields = ["email", "password", "name", "status"]
            missing_fields = [field for field in required_fields if field not in request.data]

            if missing_fields:
                return Response({"error": f"Missing required fields: {', '.join(missing_fields)}"}, status=HTTP_400_BAD_REQUEST)

            data = request.data

            # Ensure email and password are valid
            if not data.get("email") or not data.get("password"):
                return Response({"error": "Email and password are required"}, status=HTTP_400_BAD_REQUEST)

            # Check if the email is already in use
            if User.objects.filter(email=data['email']).exists():
                return Response({"error": "User with this email already exists"}, status=HTTP_400_BAD_REQUEST)

            # Create user
            user = User.objects.create_user(
                username=data['email'], 
                email=data['email'],
                password=data['password']
            )
            user.is_staff = True
            user.is_superuser = True  
            user.save()

            # Create admin profile
            admin_data = {
                "user": user.id,
                "name": data['name'],
                "email": data['email'],
                "status": data['status']
            }
            admin_serializer = serializer.AdminSerializer(data=admin_data)

            if admin_serializer.is_valid():
                admin_serializer.save()
                return Response(admin_serializer.data, status=HTTP_201_CREATED)
            else:
                user.delete()  # Rollback user creation if admin creation fails
                return Response(admin_serializer.errors, status=HTTP_400_BAD_REQUEST)

    except IntegrityError:
        """
        Returns an error response if an IntegrityError occurs (e.g., duplicate username/email).

        Response:
        {
            "error": "Integrity error, possible duplicate username or email"
        }
        Status: 400 BAD REQUEST
        """
        return Response({"error": "Integrity error, possible duplicate username or email"}, status=HTTP_400_BAD_REQUEST)

    except ValueError as ve:
        return Response({"error": f"Invalid data format: {str(ve)}"}, status=HTTP_400_BAD_REQUEST)

    except Exception as e:
        """
        Returns an error response for unexpected exceptions.

        Response:
        {
            "error": "Unexpected error: <error_message>"
        }
        Status: 500 INTERNAL SERVER ERROR
        """
        logger.error("An error occurred: %s", str(e))
        return Response({"error": f"Unexpected error: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)
    
from datetime import datetime
from django.utils.dateparse import parse_date


import logging

# Configure logger
logger = logging.getLogger(__name__)

@api_view(["GET"])
@permission_classes((IsEmployee,))
def employee_view_req(request, request_id):
    """
    Retrieve the details of a specific travel request for an employee.

    Parameters:
    - request: The HTTP request object.
    - request_id (int): The ID of the travel request.

    Returns:
    - 200 OK: If the request is found, returns the serialized travel request data.
    - 404 Not Found: If the request does not exist.
    """
    try:
        travel_request = models.TravelRequests.objects.get(pk=request_id)
    except models.TravelRequests.DoesNotExist:
        logger.error(f"Travel request {request_id} not found")
        return Response({"error": "Travel request not found"}, status=404)

    travel_serialized = TravelSerializer(travel_request)  # Create serializer instance
    return Response(travel_serialized.data)

@api_view(["GET", "POST"])
@permission_classes((IsManager,))
def manager_update_reqs(request, request_id):
    """
    Retrieve or update the status of a specific travel request by a manager.

    GET:
    - Retrieves the travel request details.
    
    POST:
    - Updates the status of the travel request.

    Parameters:
    - request: The HTTP request object.
    - request_id (int): The ID of the travel request.

    Returns:
    - 200 OK: If the request is found and processed successfully.
    - 400 Bad Request: If the provided data is invalid.
    - 404 Not Found: If the request does not exist.
    """
    query = models.TravelRequests.objects.get(pk=request_id)
    
    if request.method == "GET":
        serialized_query = serializer.TravelSerializer(query, partial=True)
        return Response(serialized_query.data, status=HTTP_200_OK)
    
    elif request.method == "POST":
        status = request.data.get("status")
        query.status = status
        
        serialized_query = serializer.TravelSerializer(query, data={"status": status}, partial=True)

        if serialized_query.is_valid():
            serialized_query.save()
            logger.info(f"Status updated for request {request_id} by manager")
            return Response({"message": "Status has been updated"}, status=HTTP_200_OK)
        else:
            logger.error(f"Error updating status for request {request_id}: {serialized_query.errors}")
            return Response(serialized_query.errors, HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes((IsManager,))
def addnote_mngr(request, request_id):
    """
    Allows a manager to add a note to an employee's travel request and notifies the employee via email.

    Parameters:
    - request: The HTTP request object containing the note.
    - request_id (int): The ID of the travel request.

    Returns:
    - 200 OK: If the note is successfully added and an email is sent.
    - 400 Bad Request: If the request does not exist.
    """
    try:
        query = models.TravelRequests.objects.get(pk=request_id)
        note = request.data.get("note")  # Get note from request
        query.note = note  # Save note to database
        query.save()

        # Get employee email
        employee_email = query.employee.user.email  # Assuming employee has a user model

        # Send email
        subject = "New Note from Your Manager"
        message = f"Dear {query.employee.user.username},\n\nYour manager has added a note:\n\n'{note}'\n\nRegards,\nCompany"
        from_email = settings.DEFAULT_FROM_EMAIL  # Use email from settings
        recipient_list = [employee_email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        logger.info(f"Manager added note to request {request_id}, email sent to {employee_email}")
        return Response({"message": "Note added & email sent successfully!"}, status=HTTP_200_OK)

    except models.TravelRequests.DoesNotExist:
        logger.error(f"Request {request_id} not found for adding note")
        return Response({"error": "Request not found"}, status=HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes((IsAdmin,))
def addnote_admin(request, request_id):
    """
    Allows an admin to add a note to an employee's travel request and notifies the employee via email.

    Parameters:
    - request: The HTTP request object containing the admin note.
    - request_id (int): The ID of the travel request.

    Returns:
    - 200 OK: If the admin note is added successfully and an email is sent.
    - 400 Bad Request: If the request does not exist or data is invalid.
    """
    try:
        admin_note = request.data.get("admin_note")

        if not admin_note:
            return Response({"error": "Admin note cannot be empty"}, status=HTTP_400_BAD_REQUEST)

        query = models.TravelRequests.objects.get(pk=request_id)
        query.admin_note = admin_note

        # Serialize and update the database
        serialized_query = serializer.TravelSerializer(
            query, data={"admin_note": admin_note}, partial=True
        )

        if serialized_query.is_valid():
            serialized_query.save()
            
            # Get employee email
            employee_email = query.employee.user.email  # Assuming employee is linked to a User model

            # Email Notification to Employee
            subject = "Admin Note Added"
            message = f"""Hi {query.employee.user.username},

Admin has added a note to your request:

"{admin_note}"

You can check the updated request at: http://127.0.0.1:8000/employee/request/{request_id}

Best regards,
Company Team"""

            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [employee_email]  

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            logger.info(f"Admin note added to request {request_id}, email sent to {employee_email}")
            return Response({"message": "Admin note has been updated and email sent to employee"}, status=HTTP_200_OK)
        else:
            logger.error(f"Error updating admin note for request {request_id}: {serialized_query.errors}")
            return Response(serialized_query.errors, status=HTTP_400_BAD_REQUEST)

    except models.TravelRequests.DoesNotExist:
        logger.error(f"Request {request_id} not found for admin note addition")
        return Response({"error": "Request not found"}, status=HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.exception(f"Unexpected error in addnote_admin: {str(e)}")
        return Response({"error": str(e)}, status=HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes((IsEmployee,))
def requestupdate_from_employees(request, request_id):
    """
    Allows ONLY the employee who created the travel request to update it and notifies the manager via email.
    """
    try:
        employee_noteupdated = request.data.get("employee_note")

        if not employee_noteupdated:
            return Response({"error": "Employee note cannot be empty"}, status=HTTP_400_BAD_REQUEST)

        # Fetch the travel request and ensure the logged-in user is the owner
        query = models.TravelRequests.objects.get(pk=request_id)

        if query.employee.user != request.user:
            return Response({"error": "You are not authorized to update this request"}, status=HTTP_403_FORBIDDEN)

        # Serialize and update the database
        serialized_query = serializer.TravelSerializer(
            query, data={"emp_update_note": employee_noteupdated}, partial=True
        )

        if serialized_query.is_valid():
            serialized_query.save()

            # Email Notification to Manager
            subject = "REQUEST UPDATED"
            message = f"""Dear {query.manager.user.username},

Your employee has updated the request:

"{employee_noteupdated}"

Please review it at: http://127.0.0.1:8000/manager/request/{request_id}

Best regards,
Company Team"""

            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [query.manager.user.email]  

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            return Response({"message": "Employee update note has been updated and email sent to manager"}, status=HTTP_200_OK)

        else:
            return Response(serialized_query.errors, status=HTTP_400_BAD_REQUEST)

    except models.TravelRequests.DoesNotExist:
        return Response({"error": "Request not found"}, status=HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=HTTP_400_BAD_REQUEST)

   


@api_view(["GET"])
@permission_classes((IsAdmin,))
def list_employee(request):
        """
    Retrieves a list of all employees.

    Parameters:
    - request: The HTTP request object.

    Returns:
    - 200 OK: A list of all employees.
    """
        if request.method == "GET":
            query = models.Employee.objects.all().values()
            return Response(list(query), status=HTTP_200_OK)    

@api_view(["GET","POST"])
@permission_classes((IsAdmin,))
def employee_management(request):
    '''
    Function for the admin to add or list the employees.
    '''
    try:
        
        if request.method == "POST":
            required_fields = ["username", "password", "name", "email", "manager_id"]
            missing_fields = [field for field in required_fields if field not in request.data]

            if missing_fields:
                return Response({"error": f"Missing required fields: {', '.join(missing_fields)}"}, status=HTTP_400_BAD_REQUEST)

            username = request.data["username"]
            password = request.data["password"]
            name = request.data["name"]
            email = request.data["email"]
            manager_id = request.data["manager_id"]
            # user_id = request.data["user"]

            form = UserCreationForm(data={"username": username, "password1": password, "password2": password})
            if form.is_valid():
                user = form.save()
                user.email = email
                user.save()
            else:
                return Response(form.errors, status=HTTP_400_BAD_REQUEST)

            employee_data = {
                "name": name,
                "username": username,
                "email": email,
                "status": "active",
                "user": user.id,  # Ensure we use the created user's ID
                "manager": manager_id
            }

            employee_serialized = serializer.EmployeeSerializer(data=employee_data)
            if employee_serialized.is_valid():
                employee_serialized.save()
                return Response({"message": "Successfully added the employee"}, status=HTTP_201_CREATED)
            else:
                return Response(employee_serialized.errors, status=HTTP_400_BAD_REQUEST)

    except IntegrityError:
        return Response({"error": "Integrity error, possible duplicate username or email"}, status=HTTP_400_BAD_REQUEST)

    except ValueError:
        return Response({"error": "Invalid data format"}, status=HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error("An error occurred: %s", str(e))
        return Response({"error": str(e)}, status=HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["GET","POST"])
@permission_classes((IsAdmin,))
def manager_management(request):
    '''
    Function for the admin to add or list the managers.
    '''
    """
    Allows an admin to add a new employee or list all employees.

    GET:
    - Retrieves a list of all employees.

    POST:
    - Adds a new employee to the system.

    Parameters:
    - request: The HTTP request object.

    Returns:
    - 201 Created: If the employee is successfully added.
    - 400 Bad Request: If required fields are missing or data is invalid.
    - 500 Internal Server Error: If an unexpected error occurs.
    """
    try:
        if request.method == "GET":
            query = models.Manager.objects.all().values()
            return Response(list(query), status=HTTP_200_OK)

        if request.method == "POST":
            required_fields = ["username", "password", "name", "email"]
            missing_fields = [field for field in required_fields if field not in request.data]

            if missing_fields:
                return Response({"error": f"Missing required fields: {', '.join(missing_fields)}"}, status=HTTP_400_BAD_REQUEST)

            username = request.data["username"]
            password = request.data["password"]
            name = request.data["name"]
            email = request.data["email"]

            form = UserCreationForm(data={"username": username, "password1": password, "password2": password})
            if form.is_valid():
                user = form.save()
                user.email = email
                user.is_staff = True 
                user.save()
            else:
                return Response(form.errors, status=HTTP_400_BAD_REQUEST)

            manager_data = {
                "name": name,
                "username": username,
                "email": email,
                "user": user.id,  # Ensure we use the created user's ID,
                "status" :"active"

            }

            manager_serialized = serializer.ManagerSerializer(data=manager_data)
            if manager_serialized.is_valid():
                manager_serialized.save()
                return Response({"message": "Successfully added the manager"}, status=HTTP_201_CREATED)
            else:
                return Response(manager_serialized.errors, status=HTTP_400_BAD_REQUEST)

    except IntegrityError:
        return Response({"error": "Integrity error, possible duplicate username or email"}, status=HTTP_400_BAD_REQUEST)

    except ValueError:
        return Response({"error": "Invalid data format"}, status=HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error("An error occurred: %s", str(e))
        return Response({"error": str(e)}, status=HTTP_500_INTERNAL_SERVER_ERROR)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


import logging

# Logger for the API
logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Ensures only authenticated users can submit requests
def travel_requests_new(request):
    """
    API endpoint for employees to submit new travel requests.

    The logged-in employee is automatically assigned, so 'employee' field is not required in the request.
    
    The manager for the employee is fetched automatically and assigned as well.
    
    Expected JSON payload:
    {
        "from_location": "New York",
        "to_location": "Los Angeles",
        "from_date": "2025-04-01",
        "to_date": "2025-04-10",
        "travel_mode": "air",
        "purpose": "Business meeting",
        "lodging_required": true,
        "accommodation_name": "Hilton",
        "accommodation_type": "Hotel",
        "additional_note": "Need a quiet room"
    }

    Returns:
        - HTTP 200 OK: If the request is successfully submitted.
        - HTTP 400 BAD REQUEST: If the submitted data is invalid.
    """
    logger.info("New travel request received.")

    # Fetch the logged-in employee (ensure they exist)
    employee = getattr(request.user, "employee", None)
    if not employee:
        return Response({"error": "Employee record not found for this user"}, status=HTTP_400_BAD_REQUEST)

    # Fetch the employee's manager (if they exist)
    manager = employee.manager
    if not manager:
        return Response({"error": "No manager assigned to this employee."}, status=HTTP_400_BAD_REQUEST)

    # Prepare the request data and automatically assign employee and manager
    request_data = request.data.copy()  # Create a copy to modify and prevent overwriting original request data
    request_data["employee"] = employee.id  # Dynamically assign employee ID
    request_data["manager"] = manager.id  # Dynamically assign manager ID

    # Deserialize and validate the request data
    serializer = NewTravelSerializer(data=request_data)

    if serializer.is_valid():
        # Save the travel request with employee and manager data
        travel_request = serializer.save()
        logger.info(f"Travel request submitted successfully for employee {employee.name}.")

        # Return success response with relevant data
        return Response({"message": "Request submitted successfully", "travel_request_id": travel_request.id}, status=HTTP_200_OK)
    else:
        # Log and return any validation errors encountered
        logger.warning(f"Invalid travel request data: {serializer.errors}")
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)



@api_view(['DELETE'])
@permission_classes((IsEmployee,))
def delete_requests_by_employees(request, request_id):
    """
    API endpoint for employees to edit or delete their travel requests.

    - PATCH: Updates specified fields of the travel request if the request exists.
    - DELETE: Deletes the request only if it is in a "pending" state.

    Args:
        request_id (int): The ID of the travel request to be modified.

    Returns:
        - HTTP 200 OK: If the request is successfully updated or deleted.
        - HTTP 404 NOT FOUND: If the request does not exist.
        - HTTP 400 BAD REQUEST: If the request cannot be deleted due to its status.
    """
    print("######################")
    try:
        query = TravelRequests.objects.get(pk=request_id)
    except TravelRequests.DoesNotExist:
        logger.error(f"Travel request {request_id} not found.")
        print("****************************")
        return Response({"error": "Travel request not found."}, HTTP_404_NOT_FOUND)
    
    if request.method == "DELETE":
        if query.status == "pending":
            query.delete()
            logger.info(f"Travel request {request_id} deleted successfully.")
            return Response({"message": "The request has been deleted successfully"})
        else:
            logger.warning(f"Deletion failed for request {request_id}. Not in pending state.")
            return Response({"message": "The request cannot be deleted as it is past pending stage."})

@api_view(['POST'])
def login(request):
    """
    API endpoint for user login.

    This view authenticates a user using the provided username and password.
    If authentication is successful, a token is generated or retrieved.

    Returns:
        - HTTP 200 OK: If authentication is successful, along with a token.
        - HTTP 400 BAD REQUEST: If username or password is missing.
        - HTTP 404 NOT FOUND: If credentials are incorrect.
    """
    username = request.data.get("username")
    password = request.data.get("password")
    
    if username is None or password is None:
        logger.warning("Login attempt failed due to missing credentials.")
        return Response({'error': 'Please provide both username and password'}, status=HTTP_400_BAD_REQUEST)
    
    user = authenticate(username=username, password=password)
    if not user:
        logger.warning("Invalid login credentials provided.")
        return Response({'error': 'Invalid Credentials'}, status=HTTP_404_NOT_FOUND)
    
    token, _ = Token.objects.get_or_create(user=user)
    logger.info(f"User {username} logged in successfully.")
    return Response({'message': "Logged in Successfully", 'token': token.key}, status=HTTP_200_OK)

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Employee
# Configure logger
logger = logging.getLogger(__name__)

@api_view(["GET"])
@permission_classes([IsEmployee])  # Only Employees can access
def filter_travel_requestsby_employee(request):
    """
    API endpoint for employees to filter their travel requests.

    Employees can filter their own travel requests based on:
        - status (optional)
        - from_date (optional, format: YYYY-MM-DD)
        - sorting by from_date, to_date, or date_submitted (default: from_date)
        - order (ascending or descending)

    Returns:
        - HTTP 200 OK: If the filtered requests are successfully retrieved.
        - HTTP 400 BAD REQUEST: If any invalid parameters are provided.
        - HTTP 403 FORBIDDEN: If the user is not an employee.
    """
    
    
    """
    API View to filter Travel Requests based on status, from_date, and sorting.
    Only Employees can access this, and they can only view their OWN travel requests.
    """
    logger.info("Filtering travel requests for employee: %s", request.user)
    
    # Ensure the user is an Employee
    try:
        employee = Employee.objects.get(user=request.user)  # Get the employee from token
    except Employee.DoesNotExist:
        logger.warning("Unauthorized access attempt by user: %s", request.user)
        return Response({"error": "Only employees can access this."}, status=HTTP_403_FORBIDDEN)

    # Get query parameters
    status_filter = request.query_params.get('status', '')  # Filter by status (optional)
    from_date_filter = request.query_params.get('from_date', '')  # Filter by from_date (optional)
    sort_field = request.query_params.get('sort', 'from_date')  # Default sort by 'from_date'
    order = request.query_params.get('order', 'asc')  # Default order 'asc' (ascending)

    if sort_field not in ['from_date', 'to_date', 'date_submitted']:
        logger.error("Invalid sort field: %s", sort_field)
        return Response({"error": "Invalid sort field. Use 'from_date', 'to_date', or 'date_submitted'."}, status=HTTP_400_BAD_REQUEST)

    # Validate order
    if order not in ['asc', 'desc']:
        logger.error("Invalid order value: %s", order)
        return Response({"error": "Invalid order value. Use 'asc' or 'desc'."}, status=HTTP_400_BAD_REQUEST)

    # Determine order_by clause
    order_by_field = f"-{sort_field}" if order == 'desc' else sort_field

    # Build query filters (Only get requests belonging to the logged-in employee)
    filters = {"employee": employee}  # Ensures only the employee's own requests are returned
    if status_filter:
        filters["status"] = status_filter  # Apply status filter if provided
    if from_date_filter:
        try:
            from_date_obj = datetime.strptime(from_date_filter, "%Y-%m-%d").date()
            filters["from_date__gte"] = from_date_obj  # Apply from_date filter
        except ValueError:
            logger.error("Invalid from_date format: %s", from_date_filter)
            return Response({"error": "Invalid from_date format. Use YYYY-MM-DD."}, status=HTTP_400_BAD_REQUEST)

    # Filter and sort Travel Requests
    travel_requests = TravelRequests.objects.filter(**filters).order_by(order_by_field)

    # Serialize data
    serialized_data = [
        {
            "from_date": req.from_date,
            "to_date": req.to_date,
            "travel_mode": req.travel_mode,
            "status": req.status,
            "date_submitted": req.date_submitted
        }
        for req in travel_requests
    ]

    logger.info("Successfully retrieved %d travel requests for employee: %s", len(travel_requests), request.user)
    return Response({"travel_requests":serialized_data}, status=HTTP_200_OK)


from .models import TravelRequests, Employee, Manager
from .permissions import IsManager  # Ensure you have this permission set up properly

# Configure logger
logger = logging.getLogger(__name__)

@api_view(["GET"])
@permission_classes([IsEmployee])  # Only Employees can access
def filter_travel_requests_by_manager(request):
    """
    API View to filter Travel Requests based on status, from_date, and sorting.
    Only Employees can access this, and they can only view their OWN travel requests.
    """
    logger.info("Filtering travel requests for employee: %s", request.user)
    
    # Ensure the user is an Employee
    try:
        employee = Employee.objects.get(user=request.user)  # Get the employee from token
    except Employee.DoesNotExist:
        logger.warning("Unauthorized access attempt by user: %s", request.user)
        return Response({"error": "Only employees can access this."}, status=HTTP_403_FORBIDDEN)

    # Get query parameters
    status_filter = request.query_params.get('status', '')  # Filter by status (optional)
    from_date_filter = request.query_params.get('from_date', '')  # Filter by from_date (optional)
    sort_field = request.query_params.get('sort', 'from_date')  # Default sort by 'from_date'
    order = request.query_params.get('order', 'asc')  # Default order 'asc' (ascending)

    if sort_field not in ['from_date', 'to_date', 'date_submitted']:
        logger.error("Invalid sort field: %s", sort_field)
        return Response({"error": "Invalid sort field. Use 'from_date', 'to_date', or 'date_submitted'."}, status=HTTP_400_BAD_REQUEST)

    # Validate order
    if order not in ['asc', 'desc']:
        logger.error("Invalid order value: %s", order)
        return Response({"error": "Invalid order value. Use 'asc' or 'desc'."}, status=HTTP_400_BAD_REQUEST)

    # Determine order_by clause
    order_by_field = f"-{sort_field}" if order == 'desc' else sort_field

    # Build query filters (Only get requests belonging to the logged-in employee)
    filters = {"employee": employee}  # Ensures only the employee's own requests are returned
    if status_filter:
        filters["status"] = status_filter  # Apply status filter if provided
    if from_date_filter:
        try:
            from_date_obj = datetime.strptime(from_date_filter, "%Y-%m-%d").date()
            filters["from_date__gte"] = from_date_obj  # Apply from_date filter
        except ValueError:
            logger.error("Invalid from_date format: %s", from_date_filter)
            return Response({"error": "Invalid from_date format. Use YYYY-MM-DD."}, status=HTTP_400_BAD_REQUEST)

    # Filter and sort Travel Requests
    travel_requests = TravelRequests.objects.filter(**filters).order_by(order_by_field)

    # Serialize data
    serialized_data = [
        {
            "from_date": req.from_date,
            "to_date": req.to_date,
            "travel_mode": req.travel_mode,
            "status": req.status,
            "date_submitted": req.date_submitted
        }
        for req in travel_requests
    ]

    logger.info("Successfully retrieved %d travel requests for employee: %s", len(travel_requests), request.user)
    return Response({"travel_requests":serialized_data}, status=HTTP_200_OK)

from .models import TravelRequests, Employee
from .permissions import IsAdmin  # Ensure this permission is correctly implemented


# Configure logger
logger = logging.getLogger(__name__)

@api_view(["GET"])
@permission_classes([IsAdmin])  # Only Admins can access
def filter_travel_requests_admin(request):
    """
    API View to fetch travel requests for all employees.
    Admins can filter by employee name & status and sort by date_submitted.
    """
    logger.info("Admin %s is filtering travel requests", request.user)

    # Get query parameters
    employee_name = request.query_params.get('first_name', '')  # Filter by employee name
    status = request.query_params.get('status', '')  # Filter by status
    order = request.query_params.get('order', 'asc')  # Default order: ascending

    # Validate sorting order
    if order not in ['asc', 'desc']:
        logger.error("Invalid order value: %s", order)
        return Response({"error": "Invalid order value. Use 'asc' or 'desc'."}, status=HTTP_400_BAD_REQUEST)

    order_by_field = 'date_submitted' if order == 'asc' else '-date_submitted'

    # Filter travel requests based on query params
    travel_requests = TravelRequests.objects.all()
    
    if employee_name:
        travel_requests = travel_requests.filter(employee__first_name__icontains=employee_name)
    
    if status:
        travel_requests = travel_requests.filter(status=status)
    
    # Apply sorting correctly
    travel_requests = travel_requests.order_by(order_by_field)

    # Fetch employees who have filtered travel requests
    employee_ids = travel_requests.values_list('employee_id', flat=True).distinct()
    employees = Employee.objects.filter(id__in=employee_ids)

    # Serialize data
    response_data = [
        {
            "employee_id": emp.id,
            "employee_name": emp.first_name,
            "travel_requests": [
                {
                    "from_date": req.from_date,
                    "to_date": req.to_date,
                    "from_location": req.from_location,
                    "travel_mode": req.travel_mode,
                    "status": req.status,
                    "date_submitted": req.date_submitted
                }
                for req in travel_requests.filter(employee=emp).order_by(order_by_field)
            ]
        }
        for emp in employees
    ]

    logger.info("Admin %s retrieved %d employees with travel requests", request.user, len(employees))
    return Response({"employees": response_data}, status=HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_manager_for_employee(request):
    user = request.user
    try:
        employee = Employee.objects.get(user=user)
        manager_name = employee.manager.name if employee.manager else "No Manager Assigned"
        return Response({'manager_name': manager_name})
    except Employee.DoesNotExist:
        return Response({'error': 'Employee not found'}, status=404)
    


@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Ensure the user is authenticated
def get_travel_requests(request):
    try:
        # Get the Employee instance for the logged-in user
        employee = get_object_or_404(Employee, user=request.user)

        # Filter travel requests for that employee
        travel_requests = TravelRequests.objects.filter(employee=employee).values()

        return Response(list(travel_requests))  # Convert queryset to list for JSON response

    except Employee.DoesNotExist:
        return Response({"error": "Employee not found"}, status=404)
    

@api_view(['PUT'])
def edit_rq_by_employee(request, request_id):
    try:
        travel_request = TravelRequests.objects.get(id=request_id)
    except TravelRequests.DoesNotExist:
        return Response({"error": "Travel request not found"}, status=status.HTTP_404_NOT_FOUND)

    # Ensure the employee making the request is the one modifying it
    employee_id = request.data.get('employee_id')  # Assuming you send employee_id in request body
    if not employee_id:
        return Response({"error": "Employee ID is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        employee = Employee.objects.get(id=employee_id)
    except Employee.DoesNotExist:
        return Response({"error": "Employee not found"}, status=status.HTTP_404_NOT_FOUND)

    if travel_request.employee != employee:
        return Response({"error": "Unauthorized: You can only edit your own requests"}, status=status.HTTP_403_FORBIDDEN)

    # Deserialize and update the travel request
    serializer = NewTravelSerializer(travel_request, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Travel request updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_employee_name_id(request):
    """ Fetch the logged-in employee's name """
    user = request.user  # Get the logged-in user

    if not hasattr(user, 'employee'):  # Check if user has an employee profile
        return Response({"error": "Employee profile not found"}, status=404)

    employee = user.employee  # Get employee object
    first_name = employee.name or ""  # Replace None with empty string
    last_name = employee.last_name or ""  # Replace None with empty string

    full_name = f"{first_name} {last_name}".strip()  # Remove extra spaces

    return Response({"name": full_name})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def manager_view_requests(request):
    try:
        # Ensure the user is a Manager
        manager = Manager.objects.get(user=request.user)

        # Fetch travel requests directly for employees under this manager
        travel_requests = TravelRequests.objects.filter(employee__manager=manager)

        serializer = TravelSerializer(travel_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    except Manager.DoesNotExist:
        return Response({"error": "You are not authorized as a manager."}, status=status.HTTP_403_FORBIDDEN)
    
from django.utils.timezone import now
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_rq_status(request, request_id):
    try:
        travel_request = TravelRequests.objects.get(id=request_id)
    except TravelRequests.DoesNotExist:
        return Response({'error': 'Travel request not found'}, status=status.HTTP_404_NOT_FOUND)

    # Extract status and optional note from request data
    new_status = request.data.get('status')
    note = request.data.get('note', '')

    # Ensure status is valid
    if new_status not in ['approved', 'rejected', 'resubmit', 'resubmitted']:
        return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)

    # Manager can only request resubmission if status is 'pending'
    if new_status == 'resubmit' and travel_request.status.lower() != 'pending':
        return Response({'error': 'More information can only be requested for pending requests'}, 
                        status=status.HTTP_400_BAD_REQUEST)

    # Employee can only resubmit if the status is 'resubmit'
    if new_status == 'resubmitted' and travel_request.status.lower() != 'resubmit':
        return Response({'error': 'You can only resubmit a request that was marked for resubmission.'}, 
                        status=status.HTTP_400_BAD_REQUEST)

    # Update travel request status
    travel_request.status = new_status
    travel_request.manager_note = note

    if new_status == 'approved':
        travel_request.approval_date = now()
    elif new_status == 'rejected':
        travel_request.rejected_date = now()
    elif new_status == 'resubmit':
        travel_request.resubmitted = True  # Manager requests more info
    elif new_status == 'resubmitted':
        travel_request.resubmitted = False  # Employee resubmits the request

    travel_request.save()

    # Send email notification
    subject = f"Update on Your Travel Request (ID: {travel_request.id})"
    message = f"Dear {travel_request.employee.name},\n\n"

    if new_status == "resubmit":
        message += "Your travel request needs additional details. Please update and resubmit."
    elif new_status == "resubmitted":
        message += "Your travel request has been successfully resubmitted."
    elif new_status == "approved":
        message += "Your travel request has been approved."
    elif new_status == "rejected":
        message += "Your travel request has been rejected."

    if note:
        message += f"\n\nManager's Note: {note}"

    message += "\n\nBest Regards,\nManagement Team"

    send_mail(
        subject,
        message,
        'noreply@yourcompany.com',  # Replace with your company's email
        [travel_request.employee.email],  # Employee's email
        fail_silently=False,
    )

    return Response({'message': f'Travel request status updated to {new_status}'}, status=status.HTTP_200_OK)




from django.utils.dateparse import parse_date
from rest_framework.exceptions import NotFound
from rest_framework import status

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsManager])
def filter_req(request):
    """
    Filters travel requests for employees under the logged-in manager.

    Query Parameters:
    - status (str): Filter by travel request status.
    - employee (str): Filter by employee name (case-insensitive).
    - from_date (YYYY-MM-DD): Start date for filtering requests.
    - to_date (YYYY-MM-DD): End date for filtering requests.
    - sort_by (str, default: "date_submitted"): Field to sort by.
    - order (str, "asc" or "desc", default: "desc"): Sorting order.
    """
    try:
        # Get filters from query params
        status_filter = request.query_params.get("status")
        employee_name = request.query_params.get("employee")
        from_date = request.query_params.get("from_date")
        to_date = request.query_params.get("to_date")
        sort_by = request.query_params.get("sort_by", "date_submitted")  # Default sorting field
        order = request.query_params.get("order", "desc")  # Default sorting order

        # Filter requests for employees under the logged-in manager
        requests = TravelRequests.objects.filter(employee__manager__user=request.user)

        # Apply filters
        if status_filter:
            requests = requests.filter(status=status_filter)
        if employee_name:
            requests = requests.filter(employee__name__icontains=employee_name)  # Case-insensitive search by employee name
        if from_date:
            requests = requests.filter(from_date__gte=parse_date(from_date))
        if to_date:
            requests = requests.filter(to_date__lte=parse_date(to_date))

        # Raise NotFound if no requests match the filters
        if not requests.exists():
            raise NotFound("No travel requests found matching your criteria.")

        # Apply sorting
        if order == "asc":
            requests = requests.order_by(sort_by)
        else:
            requests = requests.order_by(f"-{sort_by}")

        # Serialize data using Mngrsrlzr
        serializer = RequestSerializerManager(requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)  # Return a structured error
    

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])  # Only authenticated admins can access
def travel_Req_admin(request):
    """
    Get all travel requests for admin users.
    Admins can see all travel requests in the system.
    """
    # Get all travel requests from the database
    travel_requests = TravelRequests.objects.all()

    # Serialize the data using RequestSerializerAdmin
    serializer = RequestSerializerAdmin(travel_requests, many=True)

    # Return the serialized data as a response
    return Response(serializer.data, status=status.HTTP_200_OK)    


# 🔹 Resubmit Request (Only Admin)
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def resubmit_request(request, request_id):
    travel_request = get_object_or_404(TravelRequests, id=request_id)

    if "note" not in request.data:
        return Response({"error": "Resubmission note is required"}, status=status.HTTP_400_BAD_REQUEST)

    travel_request.status = "resubmit"
    travel_request.admin_note = request.data["note"]
    travel_request.save()

    # Send email notification
    send_mail(
        subject="Resubmission Request",
        message=f"Your request needs more information:\n{request.data['note']}",
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[travel_request.employee.email],
        fail_silently=False,
    )

    return Response({"message": "Request resubmitted and email sent"}, status=status.HTTP_200_OK)

# 🔹 Close Request (Only Admin, Only if approved)
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def close_request(request, request_id):
    travel_request = get_object_or_404(TravelRequests, id=request_id)

    if travel_request.status != "approved":
        return Response({"error": "Only approved requests can be closed"}, status=status.HTTP_400_BAD_REQUEST)

    travel_request.status = "closed"
    travel_request.save()

    return Response({"message": "Request closed successfully"}, status=status.HTTP_200_OK)

import json
@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsEmployee])
def update_rq_resubmission(request, request_id):
    try:
        print("Incoming request data:", json.dumps(request.data, indent=2))  #  Log received data

        employee = request.user.employee
        travel_request = TravelRequests.objects.get(id=request_id)

        if travel_request.employee is None or employee.id != travel_request.employee.id:
            return Response({"error": "You are not authorized to update this request."}, 
                            status=status.HTTP_403_FORBIDDEN)

        if travel_request.status.lower() != "resubmit":
            return Response({"error": "You can only edit requests with status 'resubmit'."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        request.data['status'] = "resubmitted"

        serializer = TravelSerializer(travel_request, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Request updated successfully!", "data": serializer.data}, 
                            status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except TravelRequests.DoesNotExist:
        return Response({"error": "Request not found."}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({"error": f"An unexpected error occurred: {str(e)}"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
