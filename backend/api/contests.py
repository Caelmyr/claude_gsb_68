"""竞赛管理 API（创建、倒计时、封榜配置、访问密码）。"""
import hmac
import os

from flask import Blueprint, jsonify, request

from backend import config
from backend.api import ok, err, require_auth, require_admin, get_current_user
from backend.storage import read_json, atomic_write_json, list_files
from backend.utils import now_iso, gen_id, frozen_now, hash_password, \
    verify_password, sign_token
from backend.judge.ranking import contest_status, contest_elapsed, reset_contest_scores

contests_bp = Blueprint("contests", __name__)

# 竞赛访问密码最大长度
MAX_PASSWORD_LEN = 128


def _load(contest_id):
    return read_json(os.path.join(config.CONTESTS_DIR, f"{contest_id}.json"))


# ---- 访问密码 ----
def has_password(c):
    """竞赛是否设置了访问密码。"""
    return bool(c and c.get("password_hash"))


def _set_password(c, password):
    salt, digest = hash_password(password)
    c["password_salt"] = salt
    c["password_hash"] = digest


def _clear_password(c):
    c.pop("password_salt", None)
    c.pop("password_hash", None)


def _normalize_password(value):
    """把请求中的密码字段规整为字符串（去除首尾空白）。"""
    if value is None:
        return ""
    return str(value).strip()


def access_token_for(c):
    """签发与当前密码绑定的访问令牌。

    令牌内容包含当前密码哈希：管理员修改或清除密码后旧令牌自动失效，
    无需服务端额外存储会话。
    """
    msg = f"contest-access:{c.get('id')}:{c.get('password_hash') or ''}"
    return sign_token(msg, config.SECRET_KEY)


def _extract_access_token():
    token = request.headers.get("X-Contest-Access", "")
    if token:
        return token
    return request.args.get("contest_token") or request.form.get("contest_token") or ""


def _need_password():
    return jsonify({
        "code": 403,
        "message": "该竞赛已设置访问密码，请输入密码后访问",
        "need_password": True,
    }), 403


def check_contest_access(c, user):
    """校验当前请求是否有权访问带密码的竞赛。

    返回 None 表示放行，否则返回可直接 return 的错误响应。
    规则：未设密码 -> 放行；管理员 -> 放行；携带有效访问令牌 -> 放行。
    """
    if not has_password(c):
        return None
    if user and user.get("role") == "admin":
        return None
    token = _extract_access_token()
    if token and hmac.compare_digest(token, access_token_for(c)):
        return None
    return _need_password()


def _decorate(c):
    if not c:
        return None
    out = dict(c)
    # 密码哈希与盐绝不下发，仅暴露是否设密
    out.pop("password_hash", None)
    out.pop("password_salt", None)
    out["has_password"] = has_password(c)
    out["status"] = contest_status(c)
    out["elapsed"] = contest_elapsed(c)
    out["frozen_now"] = frozen_now(c)
    return out


def list_all():
    contests = []
    for cid in list_files(config.CONTESTS_DIR):
        c = _load(cid)
        if c:
            contests.append(_decorate(c))
    contests.sort(key=lambda c: c.get("start_time", ""))
    return contests


@contests_bp.get("/contests")
def get_contests():
    current = get_current_user()
    is_admin = current and current.get("role") == "admin"
    contests = list_all()
    if not is_admin:
        contests = [c for c in contests if c.get("visble", True)]
    return ok({"total": len(contests), "items": contests})


@contests_bp.get("/contests/<contest_id>")
def get_contest(contest_id):
    c = _load(contest_id)
    if not c:
        return err("竞赛不存在", 404)
    user = get_current_user()
    if not c.get("visble", True) and (user is None or user.get("role") != "admin"):
        return err("竞赛不存在", 404)
    resp = check_contest_access(c, user)
    if resp is not None:
        return resp
    return ok(_decorate(c))


@contests_bp.post("/contests/<contest_id>/unlock")
def unlock_contest(contest_id):
    """校验竞赛访问密码，成功则签发访问令牌（密码变更后令牌自动失效）。"""
    c = _load(contest_id)
    if not c:
        return err("竞赛不存在", 404)
    user = get_current_user()
    if not c.get("visble", True) and (user is None or user.get("role") != "admin"):
        return err("竞赛不存在", 404)
    if not has_password(c):
        return ok({"required": False, "access_token": None})
    data = request.get_json(silent=True) or {}
    password = _normalize_password(data.get("password"))
    if not verify_password(password, c.get("password_salt"), c.get("password_hash")):
        return err("竞赛密码错误，请重新输入", 403, 403)
    return ok({"required": True, "access_token": access_token_for(c)})


@contests_bp.post("/contests")
@require_admin
def create_contest():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return err("竞赛标题不能为空", 400)
    password = _normalize_password(data.get("password"))
    if len(password) > MAX_PASSWORD_LEN:
        return err(f"访问密码过长（最多 {MAX_PASSWORD_LEN} 字符）", 400)
    contest_id = data.get("id") or gen_id("c")
    c = {
        "id": contest_id,
        "title": title,
        "description": data.get("description", ""),
        "start_time": data.get("start_time"),
        "end_time": data.get("end_time"),
        "freeze_time": data.get("freeze_time"),
        "freeze_enabled": bool(data.get("freeze_enabled", False)),
        "mode": data.get("mode", "acm"),
        "problems": data.get("problems", []),
        "visible": data.get("visible", True),
        "created_at": now_iso(),
    }
    if password:
        _set_password(c, password)
    atomic_write_json(os.path.join(config.CONTESTS_DIR, f"{contest_id}.json"), c)
    return ok(_decorate(c))


@contests_bp.put("/contests/<contest_id>")
@require_admin
def update_contest(contest_id):
    c = _load(contest_id)
    if not c:
        return err("竞赛不存在", 404)
    data = request.get_json(silent=True) or {}
    for key in ("title", "description", "start_time", "end_time", "freeze_time",
                "mode", "problems"):
        if key in data:
            c[key] = data[key]
    if "freeze_enabled" in data:
        c["freeze_enabled"] = bool(data["freeze_enabled"])
    if "visible" in data:
        c["visible"] = bool(data["visible"])
    if "password" in data:
        # 非空 -> 设置/修改密码；空字符串 -> 清除密码（恢复公开）；缺省 -> 不变
        password = _normalize_password(data.get("password"))
        if len(password) > MAX_PASSWORD_LEN:
            return err(f"访问密码过长（最多 {MAX_PASSWORD_LEN} 字符）", 400)
        if password:
            _set_password(c, password)
        else:
            _clear_password(c)
    if "title" in data and not (data["title"] or "").strip():
        return err("竞赛标题不能为空", 400)
    atomic_write_json(os.path.join(config.CONTESTS_DIR, f"{contest_id}.json"), c)
    return ok(_decorate(c))


@contests_bp.delete("/contests/<contest_id>")
@require_admin
def delete_contest(contest_id):
    p = os.path.join(config.CONTESTS_DIR, f"{contest_id}.json")
    if not os.path.exists(p):
        return err("竞赛不存在", 404)
    os.remove(p)
    reset_contest_scores(contest_id)
    return ok()


@contests_bp.post("/contests/<contest_id>/reset-scores")
@require_admin
def reset_scores(contest_id):
    reset_contest_scores(contest_id)
    return ok()
