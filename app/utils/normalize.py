import unicodedata
from typing import Tuple


ZERO_WIDTH_CHARS = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u00ad",
}


FULLWIDTH_TO_HALFWIDTH = {
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
    "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N", "Ｏ": "O",
    "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T",
    "Ｕ": "U", "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y",
    "Ｚ": "Z", "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d",
    "ｅ": "e", "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i",
    "ｊ": "j", "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n",
    "ｏ": "o", "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s",
    "ｔ": "t", "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x",
    "ｙ": "y", "ｚ": "z",
    "（": "(", "）": ")", "［": "[", "］": "]",
    "｛": "{", "｝": "}", "【": "[", "】": "]",
    "，": ",", "。": ".", "、": "\\", "；": ";", "：": ":",
    "？": "?", "！": "!", "＂": "\"", "＇": "'",
    "＼": "\\", "／": "/", "～": "~", "＠": "@",
    "＃": "#", "＄": "$", "％": "%", "＾": "^",
    "＆": "&", "＊": "*", "（": "(", "）": ")",
    "＿": "_", "＋": "+", "＝": "=", "＜": "<",
    "＞": ">", "｜": "|", "＼": "\\", "・": ".",
}


def normalize_text(text: str) -> Tuple[str, list[int]]:
    """
    预处理文本，返回 (normalized_text, position_map)
    position_map[i] = normalized_text 中第 i 个字符在原 text 中的索引
    """
    if not text:
        return "", []

    normalized_chars = []
    position_map = []

    for idx, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            continue

        if ch in FULLWIDTH_TO_HALFWIDTH:
            normalized_chars.append(FULLWIDTH_TO_HALFWIDTH[ch])
            position_map.append(idx)
            continue

        if ch == "\u3000":
            normalized_chars.append(" ")
            position_map.append(idx)
            continue

        normalized = unicodedata.normalize("NFKC", ch)
        if len(normalized) == 1:
            normalized_chars.append(normalized)
            position_map.append(idx)
        else:
            for sub_ch in normalized:
                normalized_chars.append(sub_ch)
                position_map.append(idx)

    return "".join(normalized_chars), position_map


def map_position(normalized_start: int, normalized_end: int, position_map: list[int]) -> Tuple[int, int]:
    """
    将 normalized 文本中的位置映射回原文本位置
    """
    if not position_map:
        return normalized_start, normalized_end

    orig_start = position_map[normalized_start] if normalized_start < len(position_map) else position_map[-1] + 1
    orig_end = position_map[normalized_end - 1] + 1 if normalized_end - 1 < len(position_map) else position_map[-1] + 1

    return orig_start, orig_end
