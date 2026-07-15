import subprocess


def _rule_exists(ip: str, target: str) -> bool:
    """
    INPUT 체인에 해당 규칙이 존재하는지 확인한다.
    target : "DROP" 또는 "ACCEPT"
    """
    result = subprocess.run(
        [
            "iptables",
            "-C", "INPUT",
            "-s", ip,
            "-j", target
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def add_black(ip):
    if _rule_exists(ip, "DROP"):
        return False
    
    subprocess.run([
        "iptables",
        "-A", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ], check=True)

    return True


def remove_black(ip):
    if not _rule_exists(ip, "DROP"):
        return False

    subprocess.run([
        "iptables",
        "-D", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ], check=True)

    return True


def add_white(ip):
    if _rule_exists(ip, "ACCEPT"):
        return False
    
    subprocess.run([
        "iptables",
        "-I", "INPUT", "1",
        "-s", ip,
        "-j", "ACCEPT"
    ], check=True)
   
    return True


def remove_white(ip):
    if not _rule_exists(ip, "ACCEPT"):
        return False
    
    subprocess.run([
        "iptables",
        "-D", "INPUT",
        "-s", ip,
        "-j", "ACCEPT"
    ], check=True)
    
    return True