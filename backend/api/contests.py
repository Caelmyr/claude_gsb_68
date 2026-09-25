"""竞赛管理 API（创建、倒计时、封榜配置、访问密码）。"""
import os

from flask import Blueprint, request

from backend import config
from backend.api import ok, err, require_auth, require_admin, get_current_user, \
    contest_access_granted, need_password
from backend.storage import read_json, atomic_write_json, list_files
from backend.utils import now_iso, gen_id, frozen_now, hash_password, verify_password, sign_token
from backend.judge.ranking import contest_status, contest_elapsed, reset_contest_scores

contests_bp = Blueprint("contests", __name__)


def _load(contest_id):
    return read_json(os.path.join(config.CONTESTS_DIR, f"{contest_id}.json"))


def _decorate(c):
    """补充展示字段，并剥离密码哈希等敏感字段（任何响应都不得泄露）。"""
    if not c:
        return None
    out = dict(c)
    out.pop("password_hash", None)
    out.pop("password_salt", None)
    out["has_password"] = bool(c.get("password_hash"))
    out["problem_count"] = len(c.get("problems") or [])
    out["status"] = contest_status(c)
    out["elapsed"] = contest_elapsed(c)
    out["frozen_now"] = frozen_now(c)
    return out


def _set_password(c, password):
    """设置/更新竞赛访问密码（加盐哈希存储，不存明文）。"""
    salt, digest = hash_password(password)
    c["password_salt"] = salt
    c["password_hash"] = digest


def _clear_password(c):
    """清除竞赛访问密码，恢复公开。"""
    c.pop("password_hash", None)
    c.pop("password_salt", None)


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
        # 设密竞赛的题目清单属于受保护内容，列表中不下发（解锁后可通过详情接口获取）
        for c in contests:
            if c.get("has_password"):
                c["problems"] = []
    return ok({"total": len(contests), "items": contests})


@contests_bp.get("/contests/<contest_id>")
def get_contest(contest_id):
    c = _load(contest_id)
    if not c:
        return err("竞赛不存在", 404)
    user = get_current_user()
    if not c.get("visble", True) and (user is None or user.get("role") != "admin"):
        return err("竞赛不存在", 404)
    if not contest_access_granted(c, user):
        return need_password(c)
    return ok(_decorate(c))


@contests_bp.post("/contests/<contest_id>/verify-password")
def verify_contest_password(contest_id):
    """校验竞赛访问密码，成功则签发访问令牌（前端缓存后无需重复输入）。"""
    c = _load(contest_id)
    if not c:
        return err("竞赛不存在", 404)
    user = get_current_user()
    if not c.get("visble", True) and (user is None or user.get("role") != "admin"):
        return err("竞赛不存在", 404)
    if not c.get("password_hash"):
        return ok({"has_password": False, "token": None})
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not verify_password(password, c.get("password_salt"), c.get("password_hash")):
        return err("竞赛密码错误，请重试", 403, 403)
    token = sign_token(f"contest:{contest_id}:{c['password_hash']}", config.SECRET_KEY)
    return ok({"has_password": True, "token": token})


@contests_bp.post("/contests")
@require_admin
def create_contest():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return err("竞赛标题不能为空", 400)
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
    password = (data.get("password") or "").strip()
    if password:
        _set_password(c, password)  # 留空即公开
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
    if "title" in data and not (data["title"] or "").strip():
        return err("竞赛标题不能为空", 400)
    # 访问密码：clear_password 优先清除；非空 password 则设置/修改；两者都没有则保持不变
    if data.get("clear_password"):
        _clear_password(c)
    new_password = (data.get("password") or "").strip()
    if new_password:
        _set_password(c, new_password)
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
