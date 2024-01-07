import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from flask import send_file
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from google.cloud import firestore
from flask_login import current_user, LoginManager
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from google.cloud import storage, firestore
import tempfile
app = Flask("file.store")
app.secret_key = 'secret key'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev
firestore_client = firestore.Client(project="project-name", database="database-name")
CLOUD_STORAGE_BUCKET = "storage-name"
GOOGLE_CLIENT_ID = 'secret key'
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['UPLOAD_FOLDER'] = 'uploads' 


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://web-app-file.ew.r.appspot.com/callback"
)

def add_file_to_collection(filename):
    firestore_client = firestore.Client(project="project-name", database="database-name")
    user_id = session.get('google_id')
    files_ref = firestore_client.collection('files')
    # Use the filename as the document ID
    file_ref = files_ref.document(filename)

    file_data = {
        'name': filename,
        'owner': user_id,
    }

    # Set the document data
    file_ref.set(file_data)

def delete_file_from_collection(filename):
    db = firestore.Client(project="project-name", database="database-name")
    files_ref = db.collection('files')

    # Use the filename as the document ID
    file_ref = files_ref.document(filename)

    # delete the document data
    file_ref.delete()


def login_is_required(function): 
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif', 'pdf'])])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_all_files():
    storage_client = storage.Client()
    user_id = session.get('google_id')  # Provide a default value
    bucket_name = "storage-name"  # Replace with your bucket name
    bucket = storage_client.get_bucket(bucket_name)

    all_files = []
    blobs = bucket.list_blobs()

    for blob in blobs:
        file_data = {
            'filename': blob.name,
            'storage_path': f'gs://{bucket_name}/{blob.name}',
            'id': blob.name  # You can replace this with a unique identifier for each file
        }

        # Check if the owner of the file matches the user in the session
        if is_owner(user_id, blob.name):
            all_files.append(file_data)

    return all_files

def is_owner(user_id, file_id):
    firestore_client = firestore.Client(project="project-name", database="database-name")
    files_ref = firestore_client.collection('files')
    
    # Retrieve the file document from Firestore
    file_doc = files_ref.document(file_id).get()

    # Check if the user is the owner of the file
    return file_doc.exists and file_doc.to_dict().get('owner') == user_id

# DOWNLOAD FILE -----------------------------
#
#
@app.route("/protected_area/<file_id>")
def download_blob(file_id):
    """Downloads a blob from the bucket."""
    bucket_name = "storage-name"
    source_blob_name = file_id
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    blob = bucket.blob(source_blob_name)

    # Create a temporary file to store the downloaded content
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        # Download the blob content to the temporary file
        blob.download_to_filename(temp_file.name)
        # Get the original file name from the blob metadata
        original_filename = blob.name.split("/")[-1]
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=original_filename
        )

@app.route("/delete_blob/<file_id>")
def delete_blob(file_id):
    """Deletes a blob from the bucket."""
    bucket_name = "storage-name"
    blob_name = file_id

    storage_client = storage.Client()

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    generation_match_precondition = None

    
    blob.reload()  
    generation_match_precondition = blob.generation

    blob.delete(if_generation_match=generation_match_precondition)
    delete_file_from_collection(file_id)
    return redirect("/protected_area")

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            return redirect(request.url)

        if file and allowed_file(file.filename):
            storage_client = storage.Client()

            filename = secure_filename(file.filename)

            bucket = storage_client.bucket(CLOUD_STORAGE_BUCKET)
            blob = bucket.blob(filename)
            blob.upload_from_file(file)
            add_file_to_collection(filename)
            return redirect("/protected_area")
    
    return render_template('protected_area.html')

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=10
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    return render_template("login.html")
    

@app.route("/protected_area")
@login_is_required
def protected_area():
    
    all_files = get_all_files()
    return render_template("protected_area.html", name=session['name'],user_files = get_all_files())


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
