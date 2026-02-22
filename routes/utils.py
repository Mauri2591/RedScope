from functools import wraps
from flask import session, redirect, url_for, abort

def login_required(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args,**kwargs)
    return wrapper
    
    
def require_scope(*allowed_scopes):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get('scope') not in allowed_scopes:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator