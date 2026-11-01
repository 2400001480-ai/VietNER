"""Regression tests for the explainable Vietnamese scam-message extractor."""

import unittest

from scam_detector import analyze_message


class ScamDetectorTests(unittest.TestCase):
    def entities(self, text, category):
        return [e for e in analyze_message(text)["entities"] if e["category"] == category]

    def test_extracts_vietnamese_and_international_phone_formats(self):
        text = "Gọi 0987 654 321 hoặc +84 987-654-321 ngay."
        found = self.entities(text, "Số điện thoại")
        self.assertEqual([e["text"] for e in found], ["0987 654 321", "+84 987-654-321"])

    def test_extracts_phone_spoken_as_vietnamese_digits(self):
        text = "Số của tôi là không chín tám bảy sáu năm bốn ba hai một."
        found = self.entities(text, "Số điện thoại")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["text"], "không chín tám bảy sáu năm bốn ba hai một")

    def test_account_requires_context_and_accepts_separators(self):
        text = "Mã đơn 20261030. STK nhận tiền: 1234-5678-9012."
        found = self.entities(text, "Số tài khoản")
        self.assertEqual([e["text"] for e in found], ["1234-5678-9012"])

    def test_account_can_be_spoken_as_digits(self):
        text = "Số tài khoản: một hai ba bốn năm sáu bảy tám chín không."
        found = self.entities(text, "Số tài khoản")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["text"], "một hai ba bốn năm sáu bảy tám chín không")

    def test_detects_obfuscated_and_unaccented_institutions(self):
        text = "V i e t c o m b a n k giả danh cong an gọi bạn."
        found = analyze_message(text)["entities"]
        self.assertTrue(any(e["category"] == "Ngân hàng" and e["text"].startswith("V i e t") for e in found))
        self.assertTrue(any(e["category"] == "Cơ quan công an" and e["text"] == "cong an" for e in found))

    def test_offsets_point_to_original_text(self):
        text = "Tin nhắn: +84 987 654 321"
        entity = self.entities(text, "Số điện thoại")[0]
        self.assertEqual(text[entity["start"]:entity["end"]], entity["text"])

    def test_suspicious_message_gets_explanatory_signals(self):
        result = analyze_message("Vietcombank yêu cầu chuyển tiền ngay và cung cấp OTP tại https://x.example")
        self.assertEqual(result["level"], "Cao")
        self.assertTrue(any("OTP" in signal for signal in result["signals"]))
        self.assertTrue(any("đường dẫn" in signal.lower() for signal in result["signals"]))

    def test_empty_input_is_safe(self):
        self.assertEqual(analyze_message("  "), {
            "entities": [], "signals": [], "level": "Chưa đánh giá", "score": 0
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
