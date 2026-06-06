from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_platform.web import challenge_flag_matches, validate_flag_regex


def main() -> None:
    regex_challenge = {
        "flag_type": "regex",
        "flag_pattern": r"FLAG\{user-[0-9]{3}\}",
        "flag_value": "",
    }
    assert challenge_flag_matches("FLAG{user-123}", regex_challenge)
    assert not challenge_flag_matches("xFLAG{user-123}", regex_challenge)
    assert not challenge_flag_matches("FLAG{user-abc}", regex_challenge)
    assert not challenge_flag_matches("FLAG{user-123}\nextra", regex_challenge)

    static_challenge = {
        "flag_type": "static",
        "flag_pattern": None,
        "flag_value": "FLAG{static-ok}",
    }
    assert challenge_flag_matches(" FLAG{static-ok} ", static_challenge)
    assert not challenge_flag_matches("FLAG{static-no}", static_challenge)

    assert validate_flag_regex(r"FLAG\{[a-z]+\}") is None
    assert validate_flag_regex(r"FLAG[") is not None
    print("flag checks passed")


if __name__ == "__main__":
    main()
