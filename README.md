# Trích xuất thông tin trong tin nhắn nghi lừa đảo

Ứng dụng Streamlit hỗ trợ sàng lọc SMS, email hoặc nội dung chat bằng cách đánh dấu số điện thoại, số tài khoản trong ngữ cảnh giao dịch, và tổ chức thuộc nhóm ngân hàng, cơ quan công an, nhà mạng. Ứng dụng cũng nêu các dấu hiệu đáng ngờ và đối chiếu câu mới với thư viện tình huống để đưa ra ví dụ gần nhất.

## Chạy ứng dụng

Yêu cầu Python 3.10 trở lên. Tạo môi trường ảo (khuyến nghị), cài thư viện trong `requirements.txt`, sau đó chạy:

```powershell
streamlit run app.py
```

## Mở ứng dụng trên máy khác cùng mạng

1. Chạy ứng dụng trên máy đang chứa dự án bằng lệnh ở trên. Cấu hình `.streamlit/config.toml` đã cho phép Streamlit lắng nghe kết nối mạng nội bộ ở cổng `8501`.
2. Trên máy chủ, mở PowerShell hoặc Command Prompt và chạy `ipconfig`. Ghi lại địa chỉ **IPv4** của Wi-Fi/Ethernet, thường có dạng `192.168.1.25` hoặc `10.0.0.12`.
3. Trên máy khác đang dùng cùng Wi-Fi/LAN, mở trình duyệt và truy cập `http://ĐỊA-CHỈ-IP:8501`, ví dụ `http://192.168.1.25:8501`.
4. Giữ cửa sổ Streamlit đang chạy. Nếu Windows Firewall hỏi, cho phép Python/Streamlit trên mạng **Private**. Nếu chưa truy cập được, có thể mở PowerShell bằng quyền quản trị và tạo quy tắc cho mạng riêng:

```powershell
New-NetFirewallRule -DisplayName "VietNER Streamlit (Private)" -Direction Inbound -Protocol TCP -LocalPort 8501 -Action Allow -Profile Private
```

Máy chủ và máy truy cập cần ở cùng mạng; một số mạng trường học/công ty chặn thiết bị nội bộ kết nối với nhau. Cấu hình này chưa công khai website ra Internet. Không chuyển tiếp cổng router hoặc chia sẻ ứng dụng lên mạng công cộng khi chưa có lớp đăng nhập và HTTPS.

Lần phân tích đầu tiên có thể tải mô hình ngữ nghĩa `intfloat/multilingual-e5-small` về máy (khoảng vài trăm MB), nên cần kết nối Internet. Nếu mô hình chưa tải được, ứng dụng tự chuyển sang so sánh TF-IDF và n-gram ký tự. Sau khi cài thư viện mới, khởi động lại ứng dụng.

Các quy tắc trích xuất nằm trong `scam_detector.py`; các tình huống có nhãn và câu diễn đạt lại nằm trong `scam_corpus.py`; bộ so sánh nằm trong `scenario_matcher.py`; giao diện đơn tin và CSV nằm trong `app.py`. Mô hình NER tổng quát trong `ner_model.py` không được dùng cho việc phát hiện số điện thoại/tài khoản vì bộ quy tắc chuyên biệt có thể trả về vị trí chính xác và giải thích được.

## Loại thông tin được tìm

- **Số điện thoại:** dạng nội địa `0…`, quốc tế `+84…`, và một số dấu phân cách thường gặp (dấu cách, chấm, ngoặc, gạch, gạch dưới). Các số đọc từng chữ số bằng tiếng Việt cũng được dò khi có đủ chuỗi chữ số hợp lệ.
- **Số tài khoản:** chuỗi 6–19 chữ số chỉ được trích khi gần cụm như “số tài khoản”, “STK”, “số TK”, “chuyển khoản đến/vào”, “nhận tiền qua/vào”. Cho phép dấu cách, dấu chấm, dấu gạch; có hỗ trợ chuỗi số đọc bằng chữ trong ngữ cảnh này.
- **Tổ chức:** từ điển các ngân hàng phổ biến, cơ quan công an/điều tra và nhà mạng. Tên viết hoa/thường khác nhau hoặc chèn dấu cách, dấu chấm, gạch dưới/gạch nối giữa các chữ cái được dò.
- **Dấu hiệu:** đòi OTP/mật khẩu/PIN/CVV, yêu cầu chuyển tiền/nộp phí, thúc giục, đe dọa khóa/hậu quả pháp lý, link, cài ứng dụng lạ, tự xưng tổ chức và yêu cầu giữ bí mật.

## Đối chiếu câu mới với thư viện tình huống

`scam_corpus.py` lưu 12 tình huống (10 nhóm lừa đảo, 2 nhóm đối chiếu thường) cùng các câu diễn đạt lại cho từng nhóm. Với tin nhắn mới, bộ so sánh:

1. Tạo embedding bằng Sentence Transformers và `intfloat/multilingual-e5-small`, rồi tính cosine similarity giữa câu cần phân tích và câu tham khảo.
2. Tính TF-IDF theo từ/cụm từ tiếng Việt (Underthesea), character n-grams để hỗ trợ cách viết dính/sai dấu, và RapidFuzz để so khớp tập từ khi câu đổi trật tự.
3. Kết hợp thứ hạng tương đồng, gom các câu mẫu theo tình huống và trả về ba nhóm gần nhất cùng câu tham khảo.

Nếu mô hình embedding không tải được, hệ thống vẫn so sánh bằng TF-IDF và n-gram ký tự. Điểm tương đồng dùng để xếp hạng câu tham khảo; nó **không phải xác suất**, không tự kết luận tin nhắn là lừa đảo và không thay thế điểm cảnh báo dựa trên quy tắc. Khi giáo viên đưa câu mới, câu đó vẫn được phân tích theo dấu hiệu và thực thể; thư viện chỉ giải thích ví dụ gần nhất.

## Kết quả và CSV

Mỗi thực thể có nội dung nguyên bản, nhãn, loại, điểm khớp của quy tắc và vị trí bắt đầu/kết thúc theo chỉ số ký tự Python (đếm từ 0, đầu mút cuối không bao gồm). Tab CSV xuất mức cảnh báo, điểm, dấu hiệu, các nhóm thông tin và vị trí thực thể. Tệp CSV được ghi UTF-8 có BOM để mở thuận tiện bằng Excel.

## Diễn giải và giới hạn

Điểm cảnh báo là điểm sàng lọc dựa trên quy tắc, không phải xác suất lừa đảo và không thay thế kết luận của cơ quan chức năng. Thư viện 12 tình huống là dữ liệu tham khảo ban đầu, chưa đại diện mọi kiểu lừa đảo và chưa phải tập dữ liệu gán nhãn đủ lớn để huấn luyện một bộ phân loại chính xác. Câu khó, câu mới, phủ định hoặc trích dẫn lời kẻ lừa đảo có thể làm kết quả đối chiếu sai; hãy đọc cả câu tham khảo, dấu hiệu và nội dung gốc. Từ điển tổ chức hữu hạn; tên mới, cách viết tắt lạ, chữ bị chèn ký tự ngẫu nhiên hoặc văn bản bị lỗi OCR có thể bỏ sót. Nhận diện số bằng chữ có giới hạn về biến thể tiếng Việt. Tài khoản được yêu cầu có ngữ cảnh giao dịch để hạn chế nhầm ngày tháng, mã đơn hàng và số tiền. Không có bộ nhận diện nào đảm bảo phát hiện “mọi ký tự nhỏ nhất” trong mọi cách cố tình né lọc; người dùng cần xác minh qua ứng dụng, website hoặc tổng đài chính thức.

## Quy tắc an toàn

Không nhập thông tin định danh thật nếu không cần thiết. Không cung cấp mã OTP/mật khẩu, không cài ứng dụng theo hướng dẫn trong tin nhắn, không gọi số hoặc bấm liên kết được gửi kèm; hãy tự tìm kênh liên hệ chính thức của tổ chức.
