from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
)
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson import ObjectId
import json
from flask_cors import CORS
from datetime import timedelta
import matplotlib.pyplot as plt

from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Access environment variables
database_url = os.getenv("DATABASE_URL")
secrete_key = os.getenv("SECRET_KEY")

app = Flask(__name__)
CORS(app)

# Configure Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = secrete_key  # Change this to a secure secret key
jwt = JWTManager(app)

# MongoDB connection
client = MongoClient(database_url)
db = client.task_manager_db


@app.route("/")
def home():
    return "<h1>Welcome to the Task Manager App!</h1>"


# User registration route
@app.route("/api/users/register", methods=["POST"])
def register_user():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    account_name = data.get("accountname")  # New field for account name

    # Check if the username or email already exists in the database
    if db.users.find_one({"$or": [{"username": username}, {"email": email}]}):
        return jsonify({"error": "Username or email already exists"}), 400

    # Hash the password before storing it in the database
    hashed_password = generate_password_hash(password)

    # Create a new user document with account name
    user = {
        "username": username,
        "email": email,
        "password": hashed_password,
        "accountname": account_name,  # Include account name in the user document
    }

    # Insert the user document into the database
    db.users.insert_one(user)
    return jsonify({"message": "User registered successfully"}), 201


@app.route("/api/users/login", methods=["POST"])
def login_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    # Find the user document in the database by email
    user = db.users.find_one({"email": email})

    # Check if the user exists and the password is correct
    if user and check_password_hash(user["password"], password):
       # Set expiry time to 1 hour (3600 seconds)
        expires_in = timedelta(hours=5)

# Create access token with custom expiry time
        access_token = create_access_token(identity=email, expires_delta=expires_in)

        # Include user data and access token in the response
        response_data = {
            "message": "Login successful",
            "user": {
                "username": user["username"],
                "email": user["email"],
                "accountname": user.get(
                    "accountname"
                ),  # Include account name in the response if available
            },
            "access_token": access_token,
        }
        return jsonify(response_data), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401


@app.route("/api/tasks", methods=["POST"])
@jwt_required()  # Require JWT token for this route
def create_task():
    try:
        current_user = (
            get_jwt_identity()
        )  # Get the identity (username) of the logged-in user
        data = request.json
        task = {
            "board": data["board"],
            "task": data["task"],
            "person_allocated": data["person_allocated"],
            "p_email": data.get("p_email"),  
            "status": data.get("status"),  # Optional field
            "start_date": data.get("start_date"),  # Optional field
            "end_date": data.get("end_date"),  # Optional field
            "extra": data.get("extra"),  # Optional field
            "user": current_user,  # Use the identity of the logged-in user as the user_id
            # Add more fields as needed
        }

        # Insert the task into the database
        db.tasks.insert_one(task)

        # Function to convert ObjectId to string
        def convert(o):
            if isinstance(o, ObjectId):
                return str(o)

        # Convert ObjectId to string before returning JSON response
        json_response = json.dumps(
            {"task": task, "message": "Task created successfully"}, default=convert
        )
        return json_response, 201
    except Exception as e:
        # Log the exception
        print(f"An error occurred while creating task: {e}")
        # Return an error response
        return jsonify({"error": "An error occurred while creating task"}), 500


@app.route('/api/tasks', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def get_tasks():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        # Query the database to find tasks belonging to the current user
        tasks = db.tasks.find({'user': current_user})

        # Initialize an empty list to store tasks
        tasks_list = []

        # Iterate through tasks and convert to dictionary format
        for task in tasks:
            # Check if the 'board' field exists in the task
            if 'board' in task:
                task_dict = {
                   '_id': str(task['_id']),
                    'board': task['board'],
                    'task': task['task'],
                    'person_allocated': task['person_allocated'],
                    'p_email': task.get('p_email'),
                    'status': task.get('status'),
                    'start_date': task.get('start_date'),
                    'end_date': task.get('end_date'),
                    'extra': task.get('extra'),
                    
                }
                tasks_list.append(task_dict)

        # Return tasks as JSON response
        return jsonify({'tasks': tasks_list}), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while retrieving tasks: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while retrieving tasks'}), 500

# Update Task
@app.route("/api/tasks/<_id>", methods=["PUT"])
def update_task(_id):
    try:
        data = request.json
        updated_task = {
            "board": data.get("board"),
            "task": data.get("task"),
            "person_allocated": data.get("person_allocated"),
            "p_email": data.get("p_email"),
            "status": data.get("status"),
            "start_date": data.get("start_date"),
            "end_date": data.get("end_date"),
            "extra": data.get("extra"),
            # Add more fields as needed
        }
        db.tasks.update_one({"_id": ObjectId(_id)}, {"$set": updated_task})
        return jsonify({"task": updated_task, "message": "Task updated successfully"})
    except Exception as e:
        print(f"An error occurred while updating task: {e}")
        return jsonify({"error": "An error occurred while updating task"}), 500

#delete
@app.route("/api/tasks/<_id>", methods=["DELETE"])
def delete_task(_id):
    try:
        # Convert task_id to ObjectId
        task_object_id = ObjectId(_id)
        # Use the converted ObjectId to delete the task
        db.tasks.delete_one({"_id": task_object_id})
        return jsonify({"message": "Task deleted successfully"})
    except Exception as e:
        print(f"An error occurred while deleting task: {e}")
        return jsonify({"error": "An error occurred while deleting task"}), 500

# Mark Task as Completed
@app.route("/api/tasks/<_id>/complete", methods=["PUT"])
def mark_task_as_completed(_id):
    try:
        db.tasks.update_one({"_id": ObjectId(_id)}, {"$set": {"status": "completed"}})
        return jsonify({"message": "Task marked as completed"})
    except Exception as e:
        print(f"An error occurred while marking task as completed: {e}")
        return (
            jsonify({"error": "An error occurred while marking task as completed"}),
            500,
        )


# Find Task by Name
@app.route("/api/tasks/<task_name>", methods=["GET"])
def find_task_by_name(task_name):
    try:
        task = db.tasks.find_one({"task": task_name})
        if task:
            return jsonify(task)
        else:
            return jsonify({"error": "Task not found"}), 404
    except Exception as e:
        print(f"An error occurred while finding task: {e}")
        return jsonify({"error": "An error occurred while finding task"}), 500


from flask import request

@app.route('/api/tasks/sort', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def sort_tasks_by_start_date():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        # Query the database to find tasks belonging to the current user
        tasks = db.tasks.find({'user': current_user})

        # Initialize an empty list to store tasks
        tasks_list = []

        # Iterate through tasks and convert to dictionary format
        for task in tasks:
            # Check if the 'board' field exists in the task
            if 'board' in task:
                task_dict = {
                    '_id': str(task['_id']),
                    'board': task['board'],
                    'task': task['task'],
                    'person_allocated': task['person_allocated'],
                    'p_email': task.get('p_email'),
                    'status': task.get('status'),
                    'start_date': task.get('start_date'),
                    'end_date': task.get('end_date'),
                    'extra': task.get('extra'),
                }
                tasks_list.append(task_dict)

        # Sort tasks based on start date if sortByStartdate parameter is provided
        sort_option = request.args.get('sortByStartdate')
        if sort_option == 'lowToHighSD':
            tasks_list.sort(key=lambda x: x.get('start_date', ''))  # Oldest to latest
        elif sort_option == 'HighToLowSD':
            tasks_list.sort(key=lambda x: x.get('start_date', ''), reverse=True)  # Latest to oldest

        # Return tasks as JSON response
        return jsonify({'tasks': tasks_list}), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while retrieving tasks: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while retrieving tasks'}), 500


@app.route('/api/tasks/filter', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def filter_tasks_by_status():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        status_filter = request.args.get('status')  # Get the status filter value from the request query parameters

        # Query the database to find tasks belonging to the current user and matching the specified status
        tasks = db.tasks.find({'user': current_user, 'status': status_filter})

        # Initialize an empty list to store filtered tasks
        filtered_tasks = []

        # Iterate through tasks and convert to dictionary format
        for task in tasks:
            if 'board' in task:
                task_dict = {
                    '_id': str(task['_id']),
                    'board': task['board'],
                    'task': task['task'],
                    'person_allocated': task['person_allocated'],
                    'p_email': task.get('p_email'),
                    'status': task.get('status'),
                    'start_date': task.get('start_date'),
                    'end_date': task.get('end_date'),
                    'extra': task.get('extra'),
                }
                filtered_tasks.append(task_dict)

        # Return filtered tasks as JSON response
        return jsonify({'tasks': filtered_tasks}), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while filtering tasks: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while filtering tasks'}), 500



@app.route('/api/tasks/filter-by-board', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def filter_tasks_by_board():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        board_name = request.args.get('boardName')  # Get the board name from the query parameters
        
        # Query the database to find tasks belonging to the current user and matching the board name
        tasks = db.tasks.find({'user': current_user, 'board': board_name})

        # Initialize an empty list to store tasks
        tasks_list = []

        # Iterate through tasks and convert to dictionary format
        for task in tasks:
            task_dict = {
                '_id': str(task['_id']),
                'board': task['board'],
                'task': task['task'],
                'person_allocated': task['person_allocated'],
                'p_email': task.get('p_email'),
                'status': task.get('status'),
                'start_date': task.get('start_date'),
                'end_date': task.get('end_date'),
                'extra': task.get('extra'),
            }
            tasks_list.append(task_dict)

        # Return tasks as JSON response
        return jsonify({'tasks': tasks_list}), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while filtering tasks by board: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while filtering tasks by board'}), 500
    
    
@app.route('/api/tasks/filter-by-name', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def filter_tasks_by_personname():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        person_name = request.args.get('personName')  # Get the board name from the query parameters
        
        # Query the database to find tasks belonging to the current user and matching the board name
        tasks = db.tasks.find({'user': current_user, 'person_allocated': person_name})

        # Initialize an empty list to store tasks
        tasks_list = []

        # Iterate through tasks and convert to dictionary format
        for task in tasks:
            task_dict = {
                '_id': str(task['_id']),
                'board': task['board'],
                'task': task['task'],
                'person_allocated': task['person_allocated'],
                'p_email': task.get('p_email'),
                'status': task.get('status'),
                'start_date': task.get('start_date'),
                'end_date': task.get('end_date'),
                'extra': task.get('extra'),
            }
            tasks_list.append(task_dict)

        # Return tasks as JSON response
        return jsonify({'tasks': tasks_list}), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while filtering tasks by person name: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while filtering tasks by board'}), 500
    
    
@app.route('/api/tasks/search', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def filter_tasks_by_task_name():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        task_name = request.args.get('taskName')  # Get the task name from the query parameters
        
        # Query the database to find tasks belonging to the current user and matching the task name
        tasks = db.tasks.find({'user': current_user, 'task': task_name})

        # Initialize an empty list to store tasks
        tasks_list = []

        # Iterate through tasks and convert to dictionary format
        for task in tasks:
            task_dict = {
                '_id': str(task['_id']),
                'board': task['board'],
                'task': task['task'],
                'person_allocated': task['person_allocated'],
                'p_email': task.get('p_email'),
                'status': task.get('status'),
                'start_date': task.get('start_date'),
                'end_date': task.get('end_date'),
                'extra': task.get('extra'),
            }
            tasks_list.append(task_dict)

        # Return tasks as JSON response
        return jsonify({'tasks': tasks_list}), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while filtering tasks by task name: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while filtering tasks by task name'}), 500



@app.route('/api/tasks/pie-chart', methods=['GET'])
@jwt_required()  # Require JWT token for this route
def generate_task_status_pie_chart():
    try:
        current_user = get_jwt_identity()  # Get the identity (username) of the logged-in user
        # Query the database to find tasks belonging to the current user
        tasks = db.tasks.find({'user': current_user})

        # Initialize counters for each status category
        completed_count = 0
        in_progress_count = 0
        stuck_count = 0

        # Count tasks in each status category
        for task in tasks:
            status = task.get('status')
            if status == 'completed':
                completed_count += 1
            elif status == 'in_progress':
                in_progress_count += 1
            elif status == 'stuck':
                stuck_count += 1

        # Create a dictionary containing the counts
        status_counts = {
            'completed': completed_count,
            'in_progress': in_progress_count,
            'stuck': stuck_count
        }

        # Return status counts as JSON response
        return jsonify(status_counts), 200

    except Exception as e:
        # Log the exception
        print(f"An error occurred while generating task status pie chart: {e}")
        # Return an error response
        return jsonify({'error': 'An error occurred while generating task status pie chart'}), 500

if __name__ == "__main__":
    app.run(debug=True)
