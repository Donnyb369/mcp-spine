# ruff: noqa: S608
"""
End-to-end PII scrambling test with a real Postgres MCP server.

This test is intentionally opt-in because it starts a temporary local Postgres
cluster and launches crystaldba/postgres-mcp through Spine.

Run with:
    RUN_POSTGRES_MCP_E2E=1 pytest tests/test_postgres_pii_e2e.py
"""

from __future__ import annotations

import json
import os
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_POSTGRES_MCP_E2E") != "1",
    reason="set RUN_POSTGRES_MCP_E2E=1 to run postgres-mcp e2e test",
)


def _find_command(name: str) -> str | None:
    if found := shutil.which(name):
        return found

    candidates = [
        f"/opt/homebrew/opt/postgresql*/bin/{name}",
        f"/usr/local/opt/postgresql*/bin/{name}",
        f"/Applications/Postgres.app/Contents/Versions/*/bin/{name}",
        f"/usr/lib/postgresql/*/bin/{name}",
    ]
    for pattern in candidates:
        matches = sorted(Path("/").glob(pattern.lstrip("/")))
        if matches:
            return str(matches[-1])
    return None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        cmd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def _run_postgres_or_skip(
    cmd: list[str],
    *,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess:
    try:
        return _run(cmd)
    except subprocess.CalledProcessError as exc:
        details = "\n".join(
            part
            for part in [
                exc.stdout or "",
                exc.stderr or "",
                log_path.read_text(encoding="utf-8") if log_path and log_path.exists() else "",
            ]
            if part
        )
        if "could not create shared memory segment" in details or "Operation not permitted" in details:
            pytest.skip(f"local Postgres cannot start in this environment: {details.strip()}")
        raise AssertionError(f"Postgres command failed: {cmd}\n{details}") from exc


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class SpineClient:
    def __init__(self, config_path: Path):
        self.process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "spine.cli", "serve", "--config", str(config_path)],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._next_id = 1

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def request(self, method: str, params: dict | None = None, timeout: float = 120) -> dict:
        assert self.process.stdin is not None
        msg_id = self._next_id
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            message["params"] = params

        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return self._read_response(msg_id, timeout=timeout)

    def notify(self, method: str, params: dict | None = None) -> None:
        assert self.process.stdin is not None
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def _read_response(self, msg_id: int, timeout: float) -> dict:
        assert self.process.stdout is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self.process.stderr.read() if self.process.stderr else ""
                raise AssertionError(
                    f"spine exited early with {self.process.returncode}:\n{stderr}"
                )

            readable, _, _ = select.select([self.process.stdout], [], [], 0.2)
            if not readable:
                continue

            line = self.process.stdout.readline()
            if not line:
                continue
            response = json.loads(line)
            if response.get("id") == msg_id:
                return response

        stderr = self.process.stderr.read() if self.process.stderr else ""
        raise AssertionError(f"timed out waiting for response id={msg_id}\n{stderr}")


@pytest.fixture
def temp_postgres(tmp_path: Path):
    initdb = _find_command("initdb")
    pg_ctl = _find_command("pg_ctl")
    psql = _find_command("psql")
    missing = [
        name
        for name, cmd in {"initdb": initdb, "pg_ctl": pg_ctl, "psql": psql}.items()
        if not cmd
    ]
    if missing:
        pytest.skip(f"missing local Postgres command(s): {', '.join(missing)}")

    data_dir = tmp_path / "pgdata"
    port = _free_port()
    log_path = tmp_path / "postgres.log"
    socket_dir = Path(tempfile.mkdtemp(prefix="pgsock-", dir="/tmp"))
    password_file = tmp_path / "pg-password"
    password_file.write_text("password\n", encoding="utf-8")

    _run_postgres_or_skip([
        initdb,
        "-D",
        str(data_dir),
        "-A",
        "scram-sha-256",
        "-U",
        "postgres",
        f"--pwfile={password_file}",
        "--no-locale",
    ])
    _run_postgres_or_skip([
        pg_ctl,
        "-D",
        str(data_dir),
        "-l",
        str(log_path),
        "-o",
        f"-p {port} -h 127.0.0.1 -k {socket_dir}",
        "-w",
        "start",
    ], log_path=log_path)

    uri = f"postgresql://postgres:password@127.0.0.1:{port}/postgres"
    try:
        yield {"uri": uri, "psql": psql}
    finally:
        subprocess.run(  # noqa: S603
            [pg_ctl, "-D", str(data_dir), "-m", "fast", "-w", "stop"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        shutil.rmtree(socket_dir, ignore_errors=True)


def _seed_pii_table(psql: str, database_uri: str) -> tuple[list[str], list[str]]:
    pii_values = {
        "email": "private.user@example.org",
        "parent_email_address": "guardian@example.org",
        "phone_number": "415-867-5309",
        "current_sign_in_ip": "198.51.100.10",
        "last_sign_in_ip": "198.51.100.11",
        "zipcode": "90210",
        "library_card_number": "LC-12345",
        "username": "reader-login",
        "reset_password_token": "reset-token-abc",
        "otp_secret": "otp-secret-plain",
        "profile_birthdate": "2012-05-06",
        "profile_phone_number": "212-555-0199",
        "profile_zipcode": "10001",
        "cultural_pass_number": "CP-98765",
    }
    safe_values = {
        "user_id": "1",
        "profile_id": "10",
        "profile_user_id": "1",
        "school_student_id": "12345",
        "user_first_name": "Jane",
        "user_last_name": "Reader",
        "profile_first_name": "Sam",
        "profile_last_name": "Booker",
        "role": "reader",
        "encrypted_pin": "pin-secret-abc",
        "encrypted_otp_secret": "otp-secret-encrypted",
    }

    sql = f"""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS profiles;
        CREATE TABLE users (
            id integer PRIMARY KEY,
            email character varying DEFAULT '',
            encrypted_password character varying NOT NULL DEFAULT '',
            reset_password_token character varying,
            reset_password_sent_at timestamp without time zone,
            remember_created_at timestamp without time zone,
            sign_in_count integer NOT NULL DEFAULT 0,
            current_sign_in_at timestamp without time zone,
            last_sign_in_at timestamp without time zone,
            current_sign_in_ip inet,
            last_sign_in_ip inet,
            created_at timestamp without time zone,
            updated_at timestamp without time zone,
            microsite_id integer,
            role character varying,
            deactivated boolean,
            first_name character varying,
            last_name character varying,
            state integer NOT NULL DEFAULT 1,
            zipcode character varying,
            has_library_card boolean,
            library_card_number character varying,
            language character varying,
            partner_id integer,
            library_branch_id integer,
            phone_number character varying,
            username character varying,
            parent_email_address character varying,
            default_profile_id integer,
            source_page character varying,
            encrypted_pin character varying,
            assumed_teen_or_adult boolean DEFAULT true,
            self_registered boolean DEFAULT false,
            military_branch character varying,
            military_sponsor_status character varying,
            provider character varying NOT NULL DEFAULT 'email',
            uid uuid,
            tokens jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            mobile_app_user boolean DEFAULT false,
            department_id bigint,
            region_id bigint,
            team_id bigint,
            encrypted_otp_secret character varying,
            encrypted_otp_secret_iv character varying,
            encrypted_otp_secret_salt character varying,
            consumed_timestep integer,
            otp_required_for_login boolean,
            otp_method integer,
            demo_user boolean,
            otp_secret character varying,
            unsynced boolean NOT NULL DEFAULT false
        );
        CREATE TABLE profiles (
            id integer PRIMARY KEY,
            birthdate date,
            state integer NOT NULL DEFAULT 1,
            user_id integer,
            first_name character varying,
            childs_name_honorific character varying,
            customized_filters text,
            notes text,
            created_at timestamp without time zone,
            updated_at timestamp without time zone,
            microsite_id integer,
            send_notifications boolean DEFAULT true,
            grade_level_id integer,
            send_recommendations boolean DEFAULT true,
            gender character varying,
            profile_type character varying DEFAULT 'Child',
            library_branch_id integer,
            school_id integer,
            school_student_id integer,
            last_name character varying,
            library_card_number character varying,
            has_library_card boolean,
            partner_id integer,
            zipcode character varying,
            local_area_id integer,
            logged_books_count integer,
            earned_badges_count integer,
            earned_rewards_count integer,
            cultural_pass_number character varying,
            phone_number character varying,
            age double precision NOT NULL,
            teacher_id integer,
            profile_weight integer NOT NULL DEFAULT 1,
            last_personalized_at timestamp without time zone,
            ethnicity_id integer,
            reading_group_id integer,
            image_file_name character varying,
            image_content_type character varying,
            image_file_size integer,
            image_updated_at timestamp without time zone,
            mobile_app_user boolean DEFAULT false,
            department_id bigint,
            region_id bigint,
            team_id bigint,
            connected_profile_id integer,
            demo_user boolean,
            verified_at timestamp without time zone,
            suspended_at timestamp without time zone,
            first_name_tsv tsvector,
            last_name_tsv tsvector
        );
        INSERT INTO users (
            id,
            email,
            role,
            phone_number,
            current_sign_in_ip,
            last_sign_in_ip,
            zipcode,
            library_card_number,
            username,
            parent_email_address,
            reset_password_token,
            encrypted_pin,
            encrypted_otp_secret,
            otp_secret,
            first_name,
            last_name
        )
        VALUES (
            1,
            {_sql_literal(pii_values["email"])},
            {_sql_literal(safe_values["role"])},
            {_sql_literal(pii_values["phone_number"])},
            {_sql_literal(pii_values["current_sign_in_ip"])},
            {_sql_literal(pii_values["last_sign_in_ip"])},
            {_sql_literal(pii_values["zipcode"])},
            {_sql_literal(pii_values["library_card_number"])},
            {_sql_literal(pii_values["username"])},
            {_sql_literal(pii_values["parent_email_address"])},
            {_sql_literal(pii_values["reset_password_token"])},
            {_sql_literal(safe_values["encrypted_pin"])},
            {_sql_literal(safe_values["encrypted_otp_secret"])},
            {_sql_literal(pii_values["otp_secret"])},
            {_sql_literal(safe_values["user_first_name"])},
            {_sql_literal(safe_values["user_last_name"])}
        );
        INSERT INTO profiles (
            id,
            user_id,
            birthdate,
            first_name,
            last_name,
            library_card_number,
            zipcode,
            cultural_pass_number,
            phone_number,
            school_student_id,
            age
        )
        VALUES (
            {safe_values["profile_id"]},
            {safe_values["profile_user_id"]},
            {_sql_literal(pii_values["profile_birthdate"])},
            {_sql_literal(safe_values["profile_first_name"])},
            {_sql_literal(safe_values["profile_last_name"])},
            {_sql_literal(pii_values["library_card_number"])},
            {_sql_literal(pii_values["profile_zipcode"])},
            {_sql_literal(pii_values["cultural_pass_number"])},
            {_sql_literal(pii_values["profile_phone_number"])},
            {safe_values["school_student_id"]},
            10
        );
    """
    _run([psql, database_uri, "-v", "ON_ERROR_STOP=1", "-c", sql])
    return list(pii_values.values()), list(safe_values.values())


def _write_spine_config(tmp_path: Path, database_uri: str) -> Path:
    mcp_command = os.environ.get("POSTGRES_MCP_COMMAND", "uvx")
    if not shutil.which(mcp_command):
        pytest.skip(f"{mcp_command!r} is required to launch postgres-mcp")

    mcp_args = shlex.split(
        os.environ.get("POSTGRES_MCP_ARGS", "postgres-mcp --access-mode=unrestricted")
    )
    config_path = tmp_path / "spine-postgres-pii.toml"
    config_path.write_text(
        f"""
[spine]
log_level = "info"
audit_db = {json.dumps(str(tmp_path / "audit.db"))}

[[servers]]
name = "postgres"
command = {json.dumps(mcp_command)}
args = {json.dumps(mcp_args)}
env = {{ DATABASE_URI = {json.dumps(database_uri)} }}
timeout_seconds = 180
scramble_pii_in_responses = true
scramble_pii_use_nlp = true

[state_guard]
enabled = false

[minifier]
level = 0

[security]
scrub_secrets_in_logs = true
audit_all_tool_calls = true
global_rate_limit = 120
per_tool_rate_limit = 120
""",
        encoding="utf-8",
    )
    return config_path


def _response_text(response: dict) -> str:
    return json.dumps(response, sort_keys=True)


def test_postgres_mcp_responses_do_not_leak_real_pii(tmp_path: Path, temp_postgres):
    pii_values, safe_values = _seed_pii_table(temp_postgres["psql"], temp_postgres["uri"])
    config_path = _write_spine_config(tmp_path, temp_postgres["uri"])
    client = SpineClient(config_path)

    try:
        init = client.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "postgres-pii-e2e", "version": "1.0"},
        })
        assert "error" not in init
        client.notify("notifications/initialized")

        tools = client.request("tools/list", {}, timeout=180)
        tool_names = {tool["name"] for tool in tools["result"]["tools"]}
        assert "execute_sql" in tool_names

        users_response = client.request(
            "tools/call",
            {
                "name": "execute_sql",
                "arguments": {
                    "sql": "SELECT users.* FROM users ORDER BY id",
                },
            },
            timeout=180,
        )
        assert "error" not in users_response

        profiles_response = client.request(
            "tools/call",
            {
                "name": "execute_sql",
                "arguments": {
                    "sql": "SELECT profiles.* FROM profiles ORDER BY id",
                },
            },
            timeout=180,
        )
        assert "error" not in profiles_response

        text = _response_text(users_response) + _response_text(profiles_response)
        leaked = [value for value in pii_values if value and value in text]
        assert leaked == []

        for value in safe_values:
            assert value in text
    finally:
        client.close()
