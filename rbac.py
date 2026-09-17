from functools import wraps

from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from models import User


def get_current_user():
    user_id = get_jwt_identity()
    if user_id is None:
        return None
    return User.query.get(int(user_id))


def role_required(*allowed_roles):
    """Restrict a route to one or more roles, e.g. @role_required('admin')."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            user = get_current_user()
            if user is None:
                return jsonify({"error": "User not found"}), 401
            if user.is_locked:
                return jsonify({"error": "Account is locked. Contact an administrator."}), 403
            if user.role.name not in allowed_roles:
                return jsonify({"error": "Insufficient permissions for this resource"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def any_authenticated_user(fn):
    """Any logged-in, non-locked user may access this route."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user = get_current_user()
        if user is None:
            return jsonify({"error": "User not found"}), 401
        if user.is_locked:
            return jsonify({"error": "Account is locked. Contact an administrator."}), 403
        return fn(*args, **kwargs)

    return wrapper
