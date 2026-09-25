"""API 蓝图汇总与公共辅助函数。

统一响应格式：
  {"code": 0, "data": ...}          成功
  {"code": <非0>, "message": ...}    失败
"""
import hmac
import os
from functools import wraps

from flask import Blueprint, jsonify, request

from backend import config
from backend.storage import read_json, list_files
from backend.utils import verify_token


def ok(data=None, **extra):
    payload = {"code": 0, "data": data}
    payload.update(extra)
    return jsonify(payload)


def err(message, code=1, status=200):
    return jsonify({"code": code, "message": message}), status


def _extract_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.args.get("token") or request.form.get("token")


def find_user_by_id(user_id):
    if not user_id:
        return None
    return read_json(os.path.join(config.USERS_DIR, f"{user_id}.json"))


def find_user_by_username(username):
    for uid in list_files(config.USERS_DIR):
        u = read_json(os.path.join(config.USERS_DIR, f"{uid}.json"))
        if u and u.get("username") == username:
            return u
    return None


def get_current_user():
    """从 token 解析当前用户（已登录则返回用户 dict，否则 None）。"""
    token = _extract_token()
    if not token:
        return None
    user_id = verify_token(token, config.SECRET_KEY)
    if not user_id:
        return None
    return find_user_by_id(user_id)


def require_auth(fn):
    """要求登录。"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return err("未登录或登录已过期", 401, 401)
        request.user = user
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    """要求管理员。"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return err("未登录或登录已过期", 401, 401)
        if user.get("role") != "admin":
            return err("需要管理员权限", 403, 403)
        request.user = user
        return fn(*args, **kwargs)
    return wrapper


# ---- 竞赛访问密码 ----

def _extract_contest_token():
    """从请求中提取竞赛访问令牌（请求头 / 查询参数 / JSON 体）。"""
    token = request.headers.get("X-Contest-Token", "")
    if token:
        return token
    token = request.args.get("contest_token", "")
    if token:
        return token
    if request.method in ("POST", "PUT", "PATCH"):
        data = request.get_json(silent=True) or {}
        return data.get("contest_token") or ""
    return ""


def contest_access_granted(contest, user=None):
    """判断当前请求是否有权访问设密竞赛的内容（题面、提交、榜单等）。

    规则：未设密码 -> 公开放行；管理员 -> 直接放行；
    否则需持有 verify-password 接口签发的访问令牌。
    令牌签名内容绑定当前密码哈希，修改/清除密码后旧令牌自动失效。
    """
    if not contest or not contest.get("password_hash"):
        return True
    if user is None:
        user = get_current_user()
    if user and user.get("role") == "admin":
        return True
    token = _extract_contest_token()
    if not token:
        return False
    msg = verify_token(token, config.SECRET_KEY)
    expected = f"contest:{contest.get('id')}:{contest.get('password_hash')}"
    return msg is not None and hmac.compare_digest(msg, expected)


def need_password(contest):
    """竞赛设有访问密码且请求未通过校验时的统一响应。

    附带 need_password 标记与竞赛基本信息，供前端弹出密码输入框。
    """
    return jsonify({
        "code": 1001,
        "message": "该竞赛已设置访问密码，请输入密码后访问",
        "need_password": True,
        "contest": {"id": contest.get("id"), "title": contest.get("title", ""),
                    "has_password": True},
    }), 403


# ---- 蓝图注册 ----
from backend.api.auth import auth_bp            # noqa: E402
from backend.api.problems import problems_bp    # noqa: E402
from backend.api.contests import contests_bp    # noqa: E402
from backend.api.submissions import submissions_bp  # noqa: E402
from backend.api.leaderboard import leaderboard_bp  # noqa: E402
from backend.api.forum import forum_bp          # noqa: E402
from backend.api.stats import stats_bp          # noqa: E402
from backend.api.settings import settings_bp    # noqa: E402

ALL_BLUEPRINTS = [
    auth_bp, problems_bp, contests_bp, submissions_bp,
    leaderboard_bp, forum_bp, stats_bp, settings_bp,
]


def register_all(app):
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp, url_prefix="/api")
