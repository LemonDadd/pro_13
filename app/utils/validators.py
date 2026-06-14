import re


WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
CHECK_CODES = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]


def validate_id_card(id_card: str) -> bool:
    if not id_card or len(id_card) != 18:
        return False
    id_upper = id_card.upper()
    if not re.match(r'^[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dX]$', id_upper):
        return False
    total = 0
    for i in range(17):
        total += int(id_upper[i]) * WEIGHTS[i]
    check_index = total % 11
    return CHECK_CODES[check_index] == id_upper[17]


def validate_luhn(number: str) -> bool:
    if not number or not number.isdigit():
        return False
    total = 0
    reverse_digits = number[::-1]
    for i, ch in enumerate(reverse_digits):
        digit = int(ch)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


VALIDATORS = {
    "id_card": validate_id_card,
    "luhn": validate_luhn,
}


def run_validator(validator_name: str, value: str) -> bool:
    if not validator_name:
        return True
    validator = VALIDATORS.get(validator_name.lower())
    if not validator:
        return True
    try:
        return validator(value)
    except Exception:
        return False
