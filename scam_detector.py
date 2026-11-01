"""Rule-based extraction and warning signals for Vietnamese scam messages.

The detector is intentionally explainable and dependency-free. It reports
original-text offsets so the UI can highlight precisely what was found.
"""

import re
import unicodedata

from scenario_matcher import compare_to_scenarios


# Each tuple is (display category, canonical spelling, accepted aliases).
INSTITUTIONS = [
    ("Ngân hàng", "Vietcombank", ["VCB", "Ngân hàng Ngoại thương"]),
    ("Ngân hàng", "BIDV", ["Ngân hàng Đầu tư và Phát triển Việt Nam"]),
    ("Ngân hàng", "VietinBank", ["Vietin Bank", "CTG"]),
    ("Ngân hàng", "Agribank", ["Ngân hàng Nông nghiệp"]),
    ("Ngân hàng", "Techcombank", ["TCB"]),
    ("Ngân hàng", "MB Bank", ["MBBank", "MBbank", "Ngân hàng Quân đội"]),
    ("Ngân hàng", "ACB", ["Ngân hàng Á Châu"]),
    ("Ngân hàng", "VPBank", ["VP Bank"]),
    ("Ngân hàng", "TPBank", ["TP Bank"]),
    ("Ngân hàng", "Sacombank", ["Sacombank"]),
    ("Ngân hàng", "VIB", []), ("Ngân hàng", "SHB", []),
    ("Ngân hàng", "HDBank", ["HD Bank"]), ("Ngân hàng", "Eximbank", []),
    ("Ngân hàng", "SeABank", ["SEA Bank"]), ("Ngân hàng", "OCB", []),
    ("Ngân hàng", "MSB", ["Maritime Bank"]), ("Ngân hàng", "Nam A Bank", ["NamABank"]),
    ("Ngân hàng", "VietABank", ["Viet A Bank"]), ("Ngân hàng", "Bac A Bank", ["BacABank"]),
    ("Ngân hàng", "Ngân hàng Nhà nước", ["NHNN"]),
    ("Ngân hàng", "ngân hàng", []),
    ("Cơ quan công an", "Bộ Công an", ["BCA"]),
    ("Cơ quan công an", "Công an", ["CA"]),
    ("Cơ quan công an", "Cục Cảnh sát", ["Cảnh sát"]),
    ("Cơ quan công an", "Cơ quan điều tra", []),
    ("Cơ quan công an", "Viện kiểm sát", []),
    ("Cơ quan công an", "Tòa án", ["Toà án"]),
    ("Nhà mạng", "Viettel", []), ("Nhà mạng", "VinaPhone", ["Vinaphone"]),
    ("Nhà mạng", "MobiFone", ["Mobifone"]), ("Nhà mạng", "Vietnamobile", []),
    ("Nhà mạng", "iTel", ["itel"]), ("Nhà mạng", "Gmobile", ["Gmobile"]),
    ("Nhà mạng", "nhà mạng", []),
]

SUSPICIOUS_PATTERNS = [
    ("Yêu cầu cung cấp OTP, mật khẩu hoặc mã xác thực", r"\b(?:o\s*t\s*p|mã\s*xác\s*thực|mật\s*khẩu|mã\s*pin|mã\s*cvv)\b"),
    ("Yêu cầu chuyển tiền, chuyển khoản hoặc nộp phí", r"(?:chuyển\s*(?:tiền|khoản)|nộp\s*phí|đóng\s*phí|thanh\s*toán|nạp\s*tiền)"),
    ("Thúc giục thực hiện ngay hoặc trong thời hạn ngắn", r"(?:ngay|gấp|khẩn|trong\s*hôm\s*nay|trong\s*\d+\s*(?:phút|giờ|ngày))"),
    ("Dọa khóa tài khoản, thuê bao hoặc phát sinh hậu quả pháp lý", r"(?:(?:khóa|khoá|tạm\s*ngưng|phong\s*tỏa|xử\s*lý|khởi\s*tố).{0,70}(?:tài\s*khoản|thuê\s*bao|hồ\s*sơ|vi\s*phạm)|(?:tài\s*khoản|thuê\s*bao|hồ\s*sơ).{0,70}(?:khóa|khoá|tạm\s*ngưng|phong\s*tỏa|xử\s*lý|khởi\s*tố))"),
    ("Có đường dẫn cần kiểm tra trước khi truy cập", r"(?:https?://|www\.)\S+|\b(?:bấm|nhấn|truy\s*cập)\s+(?:vào\s+)?link\b"),
    ("Yêu cầu cài ứng dụng hoặc tệp không rõ nguồn gốc", r"(?:cài\s*(?:đặt\s*)?(?:app|ứng\s*dụng|apk)|tải\s*(?:app|ứng\s*dụng|apk))"),
    ("Tự xưng là cơ quan hoặc tổ chức để yêu cầu xử lý", r"(?:chúng\s*tôi\s*là|đây\s*là|nhân\s*viên|cán\s*bộ|tôi\s*là).{0,60}(?:công\s*an|ngân\s*hàng|viettel|vinaphone|mobifone|bidv|vietcombank)"),
    ("Cô lập người nhận, yêu cầu giữ bí mật", r"(?:không\s*kể|không\s*nói|giữ\s*bí\s*mật|không\s*được\s*cho\s*ai\s*biết).{0,50}(?:người\s*khác|ai|sự\s*việc|quá\s*trình)?"),
]

_WORD_DIGITS = {
    "không": "0", "linh": "0", "lẻ": "0", "một": "1", "mốt": "1",
    "hai": "2", "ba": "3", "bốn": "4", "tư": "4", "năm": "5",
    "lăm": "5", "sáu": "6", "bảy": "7", "tám": "8", "chín": "9",
}
_PHONE_WORD_RE = re.compile(r"\b(?:không|linh|lẻ|một|mốt|hai|ba|bốn|tư|năm|lăm|sáu|bảy|tám|chín)(?:[\s,.;-]+(?:không|linh|lẻ|một|mốt|hai|ba|bốn|tư|năm|lăm|sáu|bảy|tám|chín)){8,11}\b", re.I)


def _match(text, start, end, label, category, score=1.0):
    return {"text": text[start:end], "label": label, "category": category,
            "start": start, "end": end, "score": score}


def _institution_matches(text):
    results = []
    # Search a de-accented shadow string but map every match back to the exact
    # original Python character offsets. This catches e.g. "cong an" too.
    shadow, source_positions = [], []
    for index, character in enumerate(text):
        folded = unicodedata.normalize("NFD", character)
        folded = "".join(ch for ch in folded if unicodedata.category(ch) != "Mn")
        folded = folded.replace("đ", "d").replace("Đ", "D")
        for ch in folded:
            shadow.append(ch)
            source_positions.append(index)
    shadow = "".join(shadow)
    for category, canonical, aliases in INSTITUTIONS:
        for name in [canonical, *aliases]:
            # Allow spaces, dots, hyphens and underscores inserted between
            # Latin characters (e.g. "V i e t c o m b a n k").
            folded_name = unicodedata.normalize("NFD", name)
            folded_name = "".join(ch for ch in folded_name if unicodedata.category(ch) != "Mn")
            folded_name = folded_name.replace("đ", "d").replace("Đ", "D")
            chars = [re.escape(c) for c in folded_name if c.isalnum()]
            if not chars:
                continue
            body = r"[\s._-]*".join(chars)
            pattern = r"(?<!\w)" + body + r"(?!\w)"
            for m in re.finditer(pattern, shadow, re.I | re.U):
                start, end = source_positions[m.start()], source_positions[m.end()-1] + 1
                results.append(_match(text, start, end, "ORG", category))
    return results


def _extract_phones(text):
    results = []
    # Regular digit forms; tolerate common punctuation but preserve original span.
    pattern = r"(?<!\d)(?:\+?\s*84|0)(?:[ .()\-_/]*\d){8,10}(?!\d)"
    for m in re.finditer(pattern, text):
        digits = re.sub(r"\D", "", m.group())
        if digits.startswith("84") and len(digits) in (11, 12):
            valid = True
        else:
            valid = digits.startswith("0") and len(digits) in (10, 11)
        if valid:
            results.append(_match(text, m.start(), m.end(), "PHONE", "Số điện thoại"))
    # Worded phone numbers, e.g. "không chín tám...".
    for m in _PHONE_WORD_RE.finditer(text.lower()):
        words = re.findall(r"[a-zà-ỹ]+", m.group(), re.I)
        digits = "".join(_WORD_DIGITS.get(w.lower(), "") for w in words)
        if len(digits) in (10, 11) and digits.startswith("0"):
            results.append(_match(text, m.start(), m.end(), "PHONE", "Số điện thoại", .85))
    return results


def _account_matches(text, phone_spans):
    results = []
    cue = re.compile(r"(?:số\s*tài\s*khoản|số\s*tk\b|\bstk\b|tài\s*khoản\s*(?:nhận|chuyển)?|chuyển\s*khoản\s*(?:đến|vào)|nhận\s*tiền\s*(?:qua|vào))", re.I)
    # Digits can be separated by spaces, dots or hyphens. A cue window limits
    # false positives from dates and transaction amounts elsewhere in a message.
    number = re.compile(r"(?<!\d)(?:\d[ .-]?){5,18}\d(?!\d)")
    for c in cue.finditer(text):
        lo, hi = max(0, c.start()-18), min(len(text), c.end()+85)
        for m in number.finditer(text, lo, hi):
            start, end = m.span()
            digits = re.sub(r"\D", "", m.group())
            if not 6 <= len(digits) <= 19:
                continue
            if any(start < pe and end > ps for ps, pe in phone_spans):
                continue
            # Exclude a standalone 10/11 digit phone-shaped sequence.
            if (len(digits) in (10, 11) and digits.startswith(("0", "84"))):
                continue
            results.append(_match(text, start, end, "ACCOUNT", "Số tài khoản"))

    # Digit-by-digit Vietnamese number words when explicitly introduced as an account.
    words = r"(?:không|linh|lẻ|một|mốt|hai|ba|bốn|tư|năm|lăm|sáu|bảy|tám|chín)"
    verbal = re.compile(r"\b(?:" + words + r")(?:[\s,.;-]+" + words + r"){5,18}\b", re.I)
    for c in cue.finditer(text):
        for m in verbal.finditer(text, max(0, c.end()-4), min(len(text), c.end()+110)):
            digits = "".join(_WORD_DIGITS.get(w.lower(), "") for w in re.findall(r"[a-zà-ỹ]+", m.group(), re.I))
            if 6 <= len(digits) <= 19:
                results.append(_match(text, m.start(), m.end(), "ACCOUNT", "Số tài khoản", .85))
    return results


def analyze_message(text):
    """Return extracted entities, risk signals, and an explainable risk score."""
    if not isinstance(text, str) or not text.strip():
        return {"entities": [], "signals": [], "level": "Chưa đánh giá", "score": 0,
                "scenario_comparison": {"matches": [], "method": "Chưa phân tích", "semantic_available": False}}

    phones = _extract_phones(text)
    entities = phones + _account_matches(text, [(x["start"], x["end"]) for x in phones]) + _institution_matches(text)
    # Keep the longest match in overlapping spans; category priority makes
    # account/phone detections win over generic organization fragments.
    priority = {"Số điện thoại": 0, "Số tài khoản": 1, "Ngân hàng": 2, "Cơ quan công an": 2, "Nhà mạng": 2}
    entities.sort(key=lambda x: (x["start"], -(x["end"]-x["start"]), priority.get(x["category"], 9)))
    deduped = []
    for ent in entities:
        overlaps = [old for old in deduped if ent["start"] < old["end"] and ent["end"] > old["start"]]
        if overlaps:
            continue
        deduped.append(ent)
    deduped.sort(key=lambda x: (x["start"], x["end"]))

    signals = [title for title, pattern in SUSPICIOUS_PATTERNS if re.search(pattern, text, re.I | re.U)]
    if signals and any(x["label"] == "ORG" for x in deduped):
        signals.append("Tin nhắn nhắc đến tổ chức cùng dấu hiệu đáng ngờ; hãy xác minh qua kênh chính thức")

    sensitive = bool(re.search(r"\b(?:otp|mã\s*xác\s*thực|mật\s*khẩu|mã\s*pin|cvv)\b", text, re.I))
    money = bool(re.search(r"(?:chuyển\s*(?:tiền|khoản)|nộp\s*phí|đóng\s*phí|thanh\s*toán)", text, re.I))
    urgent = bool(re.search(r"(?:khẩn|ngay|gấp|khóa|khoá|phong\s*tỏa|khởi\s*tố)", text, re.I))
    score = min(100, len(signals) * 15 + (30 if sensitive else 0) + (15 if money else 0) + (10 if urgent else 0))
    level = "Cao" if sensitive or score >= 60 else "Cần thận trọng" if score >= 30 else "Chưa thấy dấu hiệu rõ"
    comparison = compare_to_scenarios(text)
    return {"entities": deduped, "signals": signals, "level": level, "score": score,
            "scenario_comparison": comparison}
