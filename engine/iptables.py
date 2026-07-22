import subprocess
import platform
import shlex
import ipaddress

def _rule_exists(ip: str, target: str) -> bool:
    """
    INPUT 체인에 해당 규칙이 존재하는지 확인한다.
    target : "DROP" 또는 "ACCEPT"
    """
    if platform.system() != "Linux":
        return

    result = subprocess.run(
        [
            "iptables",
            "-C", "INPUT",
            "-s", ip,
            "-j", target,
            "-m", "comment", "--comment", "packet-analyzer"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def get_ordered_rules(chain="INPUT"):
    """iptables-save 출력에서 특정 체인의 규칙을 순서대로(적용 순서) 반환"""
    result = subprocess.run(
        ["iptables-save"], capture_output=True, text=True, check=True
    )

    rules = []
    default_policy = None

    for line in result.stdout.splitlines():
        line = line.strip()

        # 기본 정책 파싱: 예) :INPUT ACCEPT [0:0]
        if line.startswith(f":{chain} "):
            parts = line.split()
            default_policy = parts[1]  # ACCEPT or DROP

        # 규칙 파싱: 예) -A INPUT -s 1.2.3.4/32 -j DROP -m comment --comment "packet-analyzer"
        elif line.startswith(f"-A {chain} "):
            rules.append(_parse_rule(line))

    return rules, default_policy


def _parse_rule(line):
    """한 줄의 iptables 규칙을 dict로 파싱"""
    tokens = shlex.split(line)
    rule = {
        "src": None,      # -s
        "dst": None,      # -d
        "target": None,   # -j
        "comment": None,  # --comment
        "raw": line,
    }

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-s", "--source"):
            rule["src"] = tokens[i + 1]
            i += 2
        elif tok in ("-d", "--destination"):
            rule["dst"] = tokens[i + 1]
            i += 2
        elif tok in ("-j", "--jump"):
            rule["target"] = tokens[i + 1]
            i += 2
        elif tok == "--comment":
            rule["comment"] = tokens[i + 1]
            i += 2
        else:
            i += 1

    return rule


def _ip_match(ip, cidr):
    """cidr이 None이면 조건 없음(항상 매치), 아니면 ip가 대역에 속하는지 확인"""
    if cidr is None:
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def is_blocked(src_ip, chain="INPUT"):
    """
    IP만 가지고 순서대로 규칙을 검사.
    첫 번째로 매치되는 규칙의 target을 기준으로 판단.
    매치되는 규칙이 없으면 일단 통과시킴.
    """
    rules, default_policy = get_ordered_rules(chain)

    for rule in rules:
        if not _ip_match(src_ip, rule["src"]):
            continue

        # 여기까지 왔으면 이 규칙에 매치됨 -> 첫 매치이므로 바로 결정
        target = rule["target"]
        if target in ("DROP", "REJECT"):
            return True
        elif target == "ACCEPT":
            return False
        else:
            # 커스텀 체인으로 점프하는 경우 등은 별도 처리 필요
            continue

    # 매치되는 규칙이 없으면 일단 허용
    return False


def add_black(ip):
    if _rule_exists(ip, "DROP"):
        return False
    
    subprocess.run([
        "iptables",
        "-A", "INPUT",
        "-s", ip,
        "-j", "DROP",
        "-m", "comment", "--comment", "packet-analyzer"
    ], check=True)

    return True


def remove_black(ip):
    if not _rule_exists(ip, "DROP"):
        return False

    subprocess.run([
        "iptables",
        "-D", "INPUT",
        "-s", ip,
        "-j", "DROP",
        "-m", "comment", "--comment", "packet-analyzer"
    ], check=True)

    return True


def add_white(ip):
    if _rule_exists(ip, "ACCEPT"):
        return False
    
    subprocess.run([
        "iptables",
        "-I", "INPUT", "1",
        "-s", ip,
        "-j", "ACCEPT",
        "-m", "comment", "--comment", "packet-analyzer"

    ], check=True)
   
    return True


def remove_white(ip):
    if not _rule_exists(ip, "ACCEPT"):
        return False
    
    subprocess.run([
        "iptables",
        "-D", "INPUT",
        "-s", ip,
        "-j", "ACCEPT",
        "-m", "comment", "--comment", "packet-analyzer"
    ], check=True)
    
    return True