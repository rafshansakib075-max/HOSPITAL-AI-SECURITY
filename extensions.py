from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()

# In-memory JWT blocklist (revoked token ids). For a production system this
# should live in Redis; a Python set is sufficient for an FYP demo running
# as a single process.
JWT_BLOCKLIST = set()
