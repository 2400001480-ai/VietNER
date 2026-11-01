"""Curated reference scenarios for scam-message similarity search.

Each scenario includes the wording used by the UI and paraphrases with the
same underlying intent. They are retrieval references, not a complete training
set or proof that a new message is fraudulent.
"""

SCENARIOS = [
    {
        "id": "bank_otp", "title": "Giả mạo ngân hàng · Yêu cầu OTP", "label": "Lừa đảo",
        "sample": "[Vietcombank] Tài khoản của Quý khách bị khóa do đăng nhập bất thường. Vui lòng xác minh ngay tại https://vcb-xacminh.example hoặc gọi 0987 654 321. Số tài khoản nhận phí xác minh: 1234-5678-9012. Tuyệt đối không cung cấp mã OTP.",
        "references": [
            "Ngân hàng báo tài khoản bị khóa, gửi đường dẫn xác minh và yêu cầu nhập mã OTP để mở lại.",
            "Có người tự xưng nhân viên ngân hàng, dọa khóa tài khoản và xin mã xác thực hoặc mật khẩu.",
            "Tin nhắn giả danh ngân hàng thúc giục đăng nhập vào trang lạ để xác minh giao dịch và chuyển phí.",
        ],
    },
    {
        "id": "telco_app", "title": "Giả mạo nhà mạng · Dụ cài ứng dụng", "label": "Lừa đảo",
        "sample": "[Viettel] Thuê bao của bạn sẽ bị khóa trong hôm nay do chưa cập nhật thông tin. Hãy cài ứng dụng APK tại www.capnhat-thuebao.example và nhập mã OTP để xác nhận. Cần hỗ trợ gọi 0912-345-678.",
        "references": [
            "Nhà mạng dọa cắt thuê bao nếu không cập nhật thông tin trên đường dẫn gửi qua SMS.",
            "Tin nhắn yêu cầu cài file APK ngoài cửa hàng chính thức để cập nhật SIM và đọc mã OTP.",
            "Người lạ giả làm nhân viên Viettel hoặc nhà mạng, yêu cầu cài ứng dụng và chia sẻ mã xác thực.",
        ],
    },
    {
        "id": "police_threat", "title": "Giả danh công an · Đe dọa pháp lý", "label": "Lừa đảo",
        "sample": "Cán bộ Công an thông báo hồ sơ của bạn liên quan đến vụ án. Hãy giữ bí mật, gọi ngay số 0901 234 567 và chuyển tiền vào tài khoản 987654321012 để xác minh. Không được kể cho người thân.",
        "references": [
            "Có người tự xưng công an nói bạn dính líu vụ án, yêu cầu giữ bí mật và chuyển tiền để chứng minh vô tội.",
            "Đối tượng giả danh cơ quan điều tra dọa bắt hoặc khởi tố nếu không chuyển tiền vào tài khoản an toàn.",
            "Cuộc gọi mạo danh công an yêu cầu không nói với gia đình và cung cấp thông tin ngân hàng để xác minh.",
        ],
    },
    {
        "id": "delivery_fee", "title": "Giả danh giao hàng · Thu phí nhận bưu phẩm", "label": "Lừa đảo",
        "sample": "Đơn hàng của bạn giao không thành công. Vui lòng thanh toán phí giao lại 18.000đ tại https://giao-hang-nhanh.example trong 30 phút hoặc gọi 0888 111 222.",
        "references": [
            "Shipper báo có bưu phẩm cần giao lại và gửi link lạ để thanh toán khoản phí nhỏ.",
            "Tin nhắn giả hãng vận chuyển yêu cầu trả phí giao hàng qua trang web không rõ nguồn gốc.",
            "Đơn hàng gặp sự cố, bấm liên kết để đóng phí nhận quà hoặc cập nhật địa chỉ ngay lập tức.",
        ],
    },
    {
        "id": "tax_refund", "title": "Giả mạo cơ quan thuế · Báo hoàn tiền", "label": "Lừa đảo",
        "sample": "Cơ quan thuế thông báo bạn được hoàn thuế. Bấm https://hoanthue.example, đăng nhập tài khoản ngân hàng và cung cấp mã OTP để nhận tiền ngay hôm nay.",
        "references": [
            "Tin nhắn báo được hoàn thuế, yêu cầu nhập mật khẩu ngân hàng và OTP vào đường dẫn lạ.",
            "Kẻ gian giả danh cơ quan thuế nói có tiền hoàn trả nhưng cần phí xử lý hoặc thông tin thẻ.",
            "Thông báo nhận trợ cấp hoặc hoàn tiền của nhà nước kèm link yêu cầu xác minh tài khoản.",
        ],
    },
    {
        "id": "job_deposit", "title": "Tuyển cộng tác viên · Yêu cầu nạp tiền", "label": "Lừa đảo",
        "sample": "Bạn được chọn làm cộng tác viên chốt đơn tại nhà, thu nhập 2 triệu mỗi ngày. Chuyển khoản đặt cọc vào STK 123456789012, chuyên viên sẽ gọi 0933 456 789 hướng dẫn.",
        "references": [
            "Việc nhẹ lương cao, làm nhiệm vụ nhận hoa hồng nhưng phải nạp tiền hoặc đặt cọc trước.",
            "Tuyển cộng tác viên chốt đơn online, yêu cầu chuyển khoản để mở nhiệm vụ rồi hứa trả hoa hồng.",
            "Nhà tuyển dụng yêu cầu đóng phí hồ sơ hoặc mua gói thành viên mới được nhận việc tại nhà.",
        ],
    },
    {
        "id": "social_account", "title": "Cảnh báo tài khoản mạng xã hội · Link đăng nhập", "label": "Lừa đảo",
        "sample": "Tài khoản của bạn vi phạm tiêu chuẩn cộng đồng và sẽ bị khóa. Xác minh danh tính tại https://xacminh-tai-khoan.example ngay để tránh mất quyền truy cập.",
        "references": [
            "Mạng xã hội báo vi phạm và dọa khóa trang cá nhân nếu không đăng nhập vào trang xác minh gửi kèm.",
            "Email giả nền tảng nói tài khoản sẽ bị vô hiệu hóa, yêu cầu nhập mật khẩu qua đường dẫn lạ.",
            "Có người nhắn cần xác minh bản quyền hoặc danh tính ngay để tránh mất quyền truy cập tài khoản.",
        ],
    },
    {
        "id": "tech_support", "title": "Mạo danh hỗ trợ kỹ thuật · Cài ứng dụng", "label": "Lừa đảo",
        "sample": "Nhân viên hỗ trợ ngân hàng sẽ giúp bạn mở khóa tài khoản. Hãy cài ứng dụng APK từ đường dẫn gửi kèm và đọc mã OTP để xác nhận danh tính.",
        "references": [
            "Nhân viên hỗ trợ yêu cầu cài app điều khiển điện thoại để sửa lỗi tài khoản hoặc hoàn tiền.",
            "Người lạ hướng dẫn tải APK từ link riêng rồi yêu cầu bật quyền trợ năng và cung cấp OTP.",
            "Kỹ thuật viên ngân hàng gọi điện xin mã xác thực để hỗ trợ mở khóa tài khoản.",
        ],
    },
    {
        "id": "relative_emergency", "title": "Giả người thân cần tiền gấp · Tài khoản nhận tiền", "label": "Lừa đảo",
        "sample": "Con đây, điện thoại con bị hỏng nên đang dùng số mới 0977 222 333. Con cần chuyển tiền gấp vào tài khoản 567890123456, mẹ đừng gọi lại nhé.",
        "references": [
            "Người lạ giả con cháu nhắn đổi số điện thoại, đang gặp nạn và xin chuyển tiền gấp.",
            "Bạn bè nhắn vay tiền qua tài khoản mới, thúc giục chuyển ngay và bảo đừng gọi xác minh.",
            "Có người mạo danh người thân báo tai nạn hoặc bị giữ, yêu cầu gửi tiền đến số tài khoản lạ.",
        ],
    },
    {
        "id": "prize_fee", "title": "Thông báo trúng thưởng · Thu phí nhận quà", "label": "Lừa đảo",
        "sample": "Chúc mừng bạn trúng thưởng 50 triệu đồng. Gọi 0908 765 432 và nộp phí hồ sơ vào STK 112233445566 để nhận giải trong hôm nay.",
        "references": [
            "Bạn trúng giải lớn nhưng phải đóng thuế, phí hồ sơ hoặc phí vận chuyển trước khi nhận quà.",
            "Tin nhắn báo trúng thưởng chương trình chưa tham gia và yêu cầu chuyển khoản để nhận tiền.",
            "Đơn vị lạ thông báo nhận quà miễn phí nhưng xin phí xác nhận và thông tin tài khoản ngân hàng.",
        ],
    },
    {
        "id": "family_safe", "title": "Tin nhắn bình thường · Đối chiếu", "label": "Đối chiếu thường",
        "sample": "Mẹ nhắn nhé, chiều nay cả nhà ăn cơm lúc 18 giờ. Khi nào về thì gọi mẹ.",
        "references": [
            "Chiều nay về nhà ăn cơm lúc sáu giờ nhé, mẹ đợi con.",
            "Mình đang trên đường, lát nữa về tới nhà thì gọi cho bạn.",
            "Cuối tuần cả nhà gặp nhau ở quán quen nhé, không có gì gấp đâu.",
        ],
    },
    {
        "id": "bank_safe", "title": "Tin nhắn ngân hàng bình thường · Đối chiếu", "label": "Đối chiếu thường",
        "sample": "Thông báo: Giao dịch thanh toán thẻ tại cửa hàng thành công. Nếu không thực hiện, hãy chủ động mở ứng dụng ngân hàng chính thức để kiểm tra.",
        "references": [
            "Thông báo giao dịch thẻ thành công. Nếu không phải bạn thực hiện, hãy tự mở ứng dụng ngân hàng để kiểm tra.",
            "Ngân hàng xác nhận đã nhận tiền vào tài khoản. Vui lòng kiểm tra lịch sử giao dịch trong ứng dụng chính thức.",
            "Tin nhắn biến động số dư, chỉ thông báo giao dịch và không yêu cầu bấm link hay cung cấp mã xác thực.",
        ],
    },
]


def get_reference_rows():
    """Flatten scenario paraphrases into labeled rows for similarity search."""
    rows = []
    for scenario in SCENARIOS:
        for text in [scenario["sample"], *scenario["references"]]:
            rows.append({
                "scenario_id": scenario["id"],
                "title": scenario["title"],
                "label": scenario["label"],
                "text": text,
            })
    return rows
