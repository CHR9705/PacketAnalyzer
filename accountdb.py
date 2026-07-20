import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta

DB_PATH = "account.db"

SESSION_TTL_DAYS = 7        # 세션 토큰 유효 기간
MAX_FAILED_ATTEMPTS = 7     # 로그인 실패 허용 횟수
LOCKOUT_MINUTES = 5         # 잠금 지속 시간


def _hash_token(raw_token: str) -> str:
    # 세션 토큰은 이미 충분히 무작위(secrets.token_urlsafe)한 값이라
    # sha256 다이제스트만 저장. DB가 유출되어도 원본 토큰 복원 불가.
    return hashlib.sha256(raw_token.encode()).hexdigest()


def get_db():
    """요청마다 새 DB 커넥션을 열어서 반환합니다."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _column_exists(conn, table, column):
    cols = [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]
    return column in cols


def init_db():
    conn = get_db()

    # -------------------------------------------------
    # users
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'pending',
            last_login_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # 기존 DB 마이그레이션 (컬럼이 없을 때만 추가)
    if not _column_exists(conn, "users", "status"):
        conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'")
    if not _column_exists(conn, "users", "last_login_at"):
        conn.execute("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP")

    # -------------------------------------------------
    # sessions: 새로고침 시 로그인 유지용 토큰 (해시로만 저장 + 만료시각)
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    # -------------------------------------------------
    # login_attempts: brute-force 방지
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            email TEXT PRIMARY KEY,
            failed_count INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMP
        )
        """
    )

    # -------------------------------------------------
    # notifications: 관리자용 알림 (가입 승인 요청, 권한 변경 요청 등)
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            related_user_id INTEGER,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # -------------------------------------------------
    # messages: 계정 간 인앱 채팅
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # -------------------------------------------------
    # role_requests: 사용자가 관리자에게 보내는 권한(role) 변경 요청
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS role_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            requested_role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            resolved_by INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (resolved_by) REFERENCES users(id)
        )
        """
    )

    # -------------------------------------------------
    # audit_log: 로그인/가입/승인/권한변경 등 주요 행동 전부 기록
    # -------------------------------------------------
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            actor_email TEXT,
            action TEXT NOT NULL,
            target_user_id INTEGER,
            detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()

    _ensure_default_admin()
    cleanup_expired_sessions()


def _ensure_default_admin():
    """
    회원가입은 전부 'pending' 상태로 시작하고 admin이 승인해야 하므로,
    승인해줄 admin 계정이 최소 1명은 있어야 합니다.
    admin 계정이 하나도 없으면 기본 계정을 하나 만들어둡니다.

    !! 중요 !!: admin@local / admin123! 은 임시 비밀번호입니다.
    실사용 전에는 create_admin.py로 별도 admin 계정을 만들고 이 계정은 지우세요.
    """
    from werkzeug.security import generate_password_hash

    conn = get_db()
    admin_exists = conn.execute(
        "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    ).fetchone()
    if admin_exists is None:
        conn.execute(
            "INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, 'admin', 'approved')",
            ("admin", generate_password_hash("admin")),
        )
        conn.commit()
    conn.close()


# ---------------------------------------------------------
# 세션 토큰 (새로고침 시 로그인 유지)
# 원본 토큰은 URL(쿼리 파라미터)에만 존재, DB에는 해시값 + 만료시각만 저장
# ---------------------------------------------------------
def create_session(user_id: int) -> str:
    raw_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=SESSION_TTL_DAYS)

    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (_hash_token(raw_token), user_id, expires_at),
    )
    conn.commit()
    conn.close()
    return raw_token


def get_user_by_session(raw_token: str):
    if not raw_token:
        return None

    conn = get_db()
    row = conn.execute(
        """
        SELECT users.id, users.email, users.role, users.status, users.last_login_at,
               sessions.expires_at
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
        """,
        (_hash_token(raw_token),),
    ).fetchone()

    if row is None:
        conn.close()
        return None

    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(raw_token),))
        conn.commit()
        conn.close()
        return None

    conn.close()
    if row["status"] != "approved":
        return None
    return {
        "id": row["id"],
        "email": row["email"],
        "role": row["role"],
        "status": row["status"],
        "last_login_at": row["last_login_at"],
    }


def delete_session(raw_token: str):
    if not raw_token:
        return
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(raw_token),))
    conn.commit()
    conn.close()


def cleanup_expired_sessions():
    """만료된 세션들을 DB에서 정리합니다. init_db()에서 자동 호출됩니다."""
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.utcnow(),))
    conn.commit()
    conn.close()


# ---------------------------------------------------------
# 로그인 시도 제한 (brute-force 방지)
# ---------------------------------------------------------
def is_locked_out(email: str):
    """잠금 상태면 (True, 남은 시간(초)) 반환, 아니면 (False, 0) 반환."""
    conn = get_db()
    row = conn.execute(
        "SELECT locked_until FROM login_attempts WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if row is None or row["locked_until"] is None:
        return False, 0

    locked_until = datetime.fromisoformat(row["locked_until"])
    remaining = (locked_until - datetime.utcnow()).total_seconds()
    if remaining <= 0:
        return False, 0
    return True, int(remaining)


def record_failed_login(email: str):
    conn = get_db()
    row = conn.execute(
        "SELECT failed_count FROM login_attempts WHERE email = ?", (email,)
    ).fetchone()

    if row is None:
        conn.execute(
            "INSERT INTO login_attempts (email, failed_count) VALUES (?, 1)", (email,)
        )
    else:
        new_count = row["failed_count"] + 1
        if new_count >= MAX_FAILED_ATTEMPTS:
            locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            conn.execute(
                "UPDATE login_attempts SET failed_count = ?, locked_until = ? WHERE email = ?",
                (new_count, locked_until, email),
            )
        else:
            conn.execute(
                "UPDATE login_attempts SET failed_count = ? WHERE email = ?",
                (new_count, email),
            )
    conn.commit()
    conn.close()


def record_successful_login(email: str):
    conn = get_db()
    conn.execute(
        "UPDATE login_attempts SET failed_count = 0, locked_until = NULL WHERE email = ?",
        (email,),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------
# 알림 (notifications)
# ---------------------------------------------------------
def add_notification(ntype: str, message: str, related_user_id: int = None):
    conn = get_db()
    conn.execute(
        "INSERT INTO notifications (type, message, related_user_id) VALUES (?, ?, ?)",
        (ntype, message, related_user_id),
    )
    conn.commit()
    conn.close()


def get_unread_notification_count(ntype: str = None):
    conn = get_db()
    if ntype:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM notifications WHERE is_read = 0 AND type = ?", (ntype,)
        ).fetchone()["c"]
    else:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM notifications WHERE is_read = 0"
        ).fetchone()["c"]
    conn.close()
    return count


# ---------------------------------------------------------
# 마지막 로그인 시각
# ---------------------------------------------------------
def update_last_login(user_id: int) -> str:
    """
    users.last_login_at을 '이번 로그인 시각'으로 갱신하기 *전에*,
    이전 값(=직전 로그인 시각)을 반환합니다. 화면에 "마지막 로그인: ..."으로
    보여줄 땐 이 반환값(직전 로그인)을 쓰면 됩니다.
    """
    now = datetime.utcnow().isoformat(sep=" ", timespec="seconds")
    conn = get_db()
    previous = conn.execute(
        "SELECT last_login_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    previous_value = previous["last_login_at"] if previous else None

    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now, user_id))
    conn.commit()
    conn.close()
    return previous_value


# ---------------------------------------------------------
# 권한(role) 변경 요청
# ---------------------------------------------------------
def create_role_request(user_id: int, requested_role: str):
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM role_requests WHERE user_id = ? AND status = 'pending'",
        (user_id,),
    ).fetchone()
    if existing:
        conn.close()
        return False, "이미 처리 대기중인 권한 요청이 있습니다."

    conn.execute(
        "INSERT INTO role_requests (user_id, requested_role) VALUES (?, ?)",
        (user_id, requested_role),
    )
    conn.commit()
    user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    add_notification(
        "role_request",
        f"{user['email']} 님이 '{requested_role}' 권한을 요청했습니다.",
        related_user_id=user_id,
    )
    log_action(
        "role_request_created",
        actor_user_id=user_id,
        actor_email=user["email"],
        target_user_id=user_id,
        detail=f"requested_role={requested_role}",
    )
    return True, "권한 변경 요청을 관리자에게 전달했습니다."


def get_my_role_requests(user_id: int, limit: int = 5):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM role_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_pending_role_requests():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT role_requests.id, role_requests.requested_role, role_requests.created_at,
               users.id AS user_id, users.email, users.role AS current_role
        FROM role_requests
        JOIN users ON users.id = role_requests.user_id
        WHERE role_requests.status = 'pending'
        ORDER BY role_requests.created_at
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def resolve_role_request(request_id: int, approve: bool, admin_user_id: int, admin_email: str):
    conn = get_db()
    req = conn.execute("SELECT * FROM role_requests WHERE id = ?", (request_id,)).fetchone()
    if req is None:
        conn.close()
        return False, "요청을 찾을 수 없습니다."

    user = conn.execute("SELECT * FROM users WHERE id = ?", (req["user_id"],)).fetchone()
    new_status = "approved" if approve else "rejected"

    conn.execute(
        "UPDATE role_requests SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ? WHERE id = ?",
        (new_status, admin_user_id, request_id),
    )
    if approve:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (req["requested_role"], user["id"]))
    conn.execute(
        "UPDATE notifications SET is_read = 1 WHERE related_user_id = ? AND type = 'role_request'",
        (user["id"],),
    )
    conn.commit()
    conn.close()

    log_action(
        "role_request_resolved",
        actor_user_id=admin_user_id,
        actor_email=admin_email,
        target_user_id=user["id"],
        detail=f"request_id={request_id}, requested_role={req['requested_role']}, result={new_status}",
    )
    return True, f"{user['email']} 님의 요청을 {'승인' if approve else '거절'}했습니다."


# ---------------------------------------------------------
# 감사 로그 (Audit Log)
# 로그인 성공/실패, 가입, 승인/거절, 권한 요청/승인/거절, 로그아웃 등을 기록
# ---------------------------------------------------------
def log_action(action: str, actor_user_id: int = None, actor_email: str = None,
                target_user_id: int = None, detail: str = None):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_log (actor_user_id, actor_email, action, target_user_id, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_user_id, actor_email, action, target_user_id, detail),
    )
    conn.commit()
    conn.close()


def get_audit_log(limit: int = 300):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]