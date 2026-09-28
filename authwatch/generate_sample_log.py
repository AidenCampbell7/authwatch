"""
Generate a realistic SSH auth.log for testing.

Embeds four attack patterns the detection engine should find:
  1. Brute force      - many failures from one IP against one account
  2. Password spray   - one IP, many accounts, few attempts each
  3. Off-hours login  - successful auth at 3am
  4. New-IP login     - successful auth from an IP never seen before

Usage:  python3 -m authwatch.generate_sample_log > data/auth.log
"""
import random
from datetime import datetime, timedelta

HOST = "webserver"
NORMAL_USERS = ["aiden", "deploy", "jenkins", "postgres"]
OFFICE_IPS = ["192.168.1.50", "192.168.1.51", "10.0.4.12"]
SPRAY_USERS = ["admin", "root", "test", "oracle", "ubuntu", "git", "ftp", "mysql"]

START = datetime(2026, 3, 10, 0, 0, 0)


def line(ts: datetime, pid: int, msg: str) -> str:
    # syslog format: "Mar 10 06:52:12 webserver sshd[12345]: <msg>"
    return f"{ts.strftime('%b %e %H:%M:%S')} {HOST} sshd[{pid}]: {msg}"


def build() -> list[str]:
    rng = random.Random(1337)   # fixed seed => reproducible output
    out: list[str] = []
    pid = 10000

    def nextpid() -> int:
        nonlocal pid
        pid += rng.randint(1, 30)
        return pid

    # ---- baseline: ordinary workday logins from office IPs ----
    for hour in range(8, 18):
        for _ in range(rng.randint(1, 3)):
            ts = START + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            user = rng.choice(NORMAL_USERS)
            ip = rng.choice(OFFICE_IPS)
            out.append(line(ts, nextpid(),
                            f"Accepted password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2"))

    # a few harmless typo'd passwords - should NOT trip brute force
    for _ in range(4):
        ts = START + timedelta(hours=rng.randint(9, 16), minutes=rng.randint(0, 59))
        out.append(line(ts, nextpid(),
                        f"Failed password for {rng.choice(NORMAL_USERS)} from {rng.choice(OFFICE_IPS)} "
                        f"port {rng.randint(40000, 60000)} ssh2"))

    # ---- 1. brute force: 40 failures against 'root' from one IP in ~6 minutes ----
    attacker = "203.0.113.42"
    t = START + timedelta(hours=2, minutes=14)
    for i in range(40):
        t += timedelta(seconds=rng.randint(5, 12))
        out.append(line(t, nextpid(),
                        f"Failed password for root from {attacker} port {rng.randint(40000, 60000)} ssh2"))

    # ---- 2. password spray: one IP, 8 accounts, 2 attempts each ----
    sprayer = "198.51.100.7"
    t = START + timedelta(hours=4, minutes=30)
    for user in SPRAY_USERS:
        for _ in range(2):
            t += timedelta(seconds=rng.randint(20, 90))
            verb = (f"Failed password for invalid user {user}"
                    if user in ("test", "oracle", "ftp") else
                    f"Failed password for {user}")
            out.append(line(t, nextpid(), f"{verb} from {sprayer} port {rng.randint(40000, 60000)} ssh2"))

    # ---- 3. off-hours success: legitimate account, 03:12 ----
    t = START + timedelta(hours=3, minutes=12)
    out.append(line(t, nextpid(),
                    f"Accepted password for deploy from 192.168.1.50 port 51999 ssh2"))

    # ---- 4. new-IP success: known account, IP never seen before ----
    t = START + timedelta(hours=21, minutes=6)
    out.append(line(t, nextpid(),
                    f"Accepted publickey for aiden from 45.77.201.9 port 52210 ssh2"))

    # noise the parser must ignore
    out.append(line(START + timedelta(hours=12), nextpid(), "Received disconnect from 192.168.1.50: 11: disconnected"))
    out.append(line(START + timedelta(hours=12, minutes=1), nextpid(), "pam_unix(sshd:session): session opened for user aiden"))

    out.sort(key=lambda s: datetime.strptime(s[:15].strip(), "%b %d %H:%M:%S"))
    return out


if __name__ == "__main__":
    print("\n".join(build()))
