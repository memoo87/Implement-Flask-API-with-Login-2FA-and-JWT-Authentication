from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import mysql.connector
import bcrypt
import pyotp
import qrcode
import io

# Initialize Flask app and API
app = Flask(__name__)
api = Api(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a strong secret key
jwt = JWTManager(app)

# Database Connection Function
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",  # Add your MySQL password if needed
        database="impo"
    )

# User Registration
class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {"message": "Username and password are required"}, 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        twofa_secret = pyotp.random_base32()
        
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                           (username, hashed_password, twofa_secret))
            conn.commit()
            return {"message": "User registered successfully", "2FA_secret": twofa_secret}, 201
        except:
            return {"message": "User already exists"}, 400
        finally:
            cursor.close()
            conn.close()

# Generate QR Code for Google Authenticator
class GenerateQRCode(Resource):
    def get(self, username):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            return {"message": "User not found"}, 404
        
        otp_uri = pyotp.totp.TOTP(user["twofa_secret"]).provisioning_uri(username, issuer_name="FlaskApp")
        qr = qrcode.make(otp_uri)
        
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        img_io.seek(0)
        
        return {"otp_uri": otp_uri}

# Login with 2FA
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp_code')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return {"message": "Invalid username or password"}, 401
        
        totp = pyotp.TOTP(user['twofa_secret'])
        if not totp.verify(otp_code):
            return {"message": "Invalid 2FA code"}, 401
        
        token = create_access_token(identity=username, expires_delta=False)
        return {"message": "Login successful", "token": token}

# CRUD Operations for Products
class CreateProduct(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                       (data['name'], data['description'], data['price'], data['quantity']))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Product created successfully"}, 201

class GetProducts(Resource):
    @jwt_required()
    def get(self):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        cursor.close()
        conn.close()
        return {"products": products}

class UpdateProduct(Resource):
    @jwt_required()
    def put(self, product_id):
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                       (data['name'], data['description'], data['price'], data['quantity'], product_id))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Product updated successfully"}

class DeleteProduct(Resource):
    @jwt_required()
    def delete(self, product_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Product deleted successfully"}

# Define Routes
api.add_resource(Register, "/register")
api.add_resource(GenerateQRCode, "/qrcode/<string:username>")
api.add_resource(Login, "/login")
api.add_resource(CreateProduct, "/product")
api.add_resource(GetProducts, "/products")
api.add_resource(UpdateProduct, "/product/<int:product_id>")
api.add_resource(DeleteProduct, "/product/<int:product_id>")

if __name__ == "__main__":
    app.run(debug=True)