import html
import base64
from pathlib import Path
import pandas as pd
import streamlit as st

from scam_detector import analyze_message
from scam_corpus import SCENARIOS

LOGO_PATH = Path(__file__).parent / "assets" / "fourt-logo.png"
LOGO_DATA = base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")

st.set_page_config(
    page_title="Cảnh báo tin nhắn nghi lừa đảo",
    page_icon=str(LOGO_PATH),
    layout="wide",
    initial_sidebar_state="expanded",
)

COLORS = {
    "Số điện thoại": ("#112B49", "#60B7FF"),
    "Số tài khoản": ("#332911", "#F5C451"),
    "Đường dẫn / URL": ("#351C31", "#FF8FCB"),
    "Ngân hàng": ("#10352F", "#51D7BA"),
    "Cơ quan công an": ("#351C31", "#F28BCC"),
    "Nhà mạng": ("#282149", "#B7A2FF"),
}

st.markdown("""
<style>
.stApp {background:radial-gradient(ellipse at 12% -5%,rgba(0,132,255,.15),transparent 33%),radial-gradient(ellipse at 92% 30%,rgba(0,220,190,.055),transparent 28%),#070A10;color:#E7EDF7}
.block-container {max-width:1240px;padding-top:1.7rem;padding-bottom:3rem}
[data-testid="stSidebar"] {background:#0A0E15;border-right:1px solid #1D2735}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {color:#96A4B8;line-height:1.65}
[data-testid="stSidebar"] h2,[data-testid="stSidebar"] h3 {color:#EAF2FD}
.hero {position:relative;overflow:hidden;display:flex;align-items:center;gap:25px;background:linear-gradient(115deg,#0B111B 0%,#101D2C 64%,#0B1520 100%);border:1px solid #20364B;border-radius:22px;padding:26px 32px;margin-bottom:26px;box-shadow:0 16px 45px rgba(0,0,0,.25)}
.hero:after {content:'';position:absolute;inset:0;background:linear-gradient(110deg,transparent 40%,rgba(0,153,255,.055));pointer-events:none}
.hero-logo {width:100px;height:100px;flex:0 0 100px;object-fit:cover;border-radius:17px;border:1px solid #21394D;box-shadow:0 0 28px rgba(0,137,255,.16)}
.hero h1 {position:relative;color:#F2F7FF;font-size:30px;letter-spacing:-.55px;font-weight:800;margin:8px 0 9px;z-index:1}
.hero p {position:relative;color:#A6B5C9;font-size:14px;line-height:1.75;margin:0;max-width:780px;z-index:1}
.eyebrow {color:#47C8FF;font-size:10px;text-transform:uppercase;letter-spacing:2px;font-weight:850}
.section-title {color:#E7EDF7;font-size:19px;font-weight:760;margin:12px 0 4px;letter-spacing:-.2px}
.section-subtitle {color:#8796AA;font-size:13px;margin:0 0 14px}
.result-card {background:#0D131D;border:1px solid #202C3B;border-radius:16px;padding:23px 25px;line-height:2.45;font-size:16px;white-space:pre-wrap;overflow-wrap:anywhere;box-shadow:0 8px 24px rgba(0,0,0,.18);color:#DCE5F0}
.entity-chip {display:inline-block;padding:2px 5px 2px 10px;margin:2px;border-radius:8px;font-weight:680;white-space:nowrap}
.entity-chip sup {display:inline-block;margin-left:5px;padding:2px 6px;border-radius:5px;background:rgba(255,255,255,.82);color:#263244;font-size:8px;line-height:1.5;font-weight:850;letter-spacing:.35px}
.risk-high,.risk-medium,.risk-low {border-radius:14px;padding:17px 20px;margin:10px 0 16px;box-shadow:0 7px 22px rgba(0,0,0,.14)}
.risk-high {background:#251316;border:1px solid #693039;color:#FF9E9E}
.risk-medium {background:#241C10;border:1px solid #68502A;color:#FFD17A}
.risk-low {background:#10221B;border:1px solid #285741;color:#80E0B0}
.legend {display:flex;align-items:center;box-sizing:border-box;width:100%;min-height:42px;padding:10px 13px;border-radius:10px;margin:6px 0;font-size:12px;font-weight:750;letter-spacing:.1px}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p:has(.legend) {margin:7px 0}
div[data-testid="stMetric"] {background:#0D131D;border:1px solid #202C3B;padding:15px 17px;border-radius:14px;box-shadow:0 5px 18px rgba(0,0,0,.14)}
div[data-testid="stMetricLabel"] {color:#8C9BAF;font-size:12px;font-weight:650}
div[data-testid="stMetricValue"] {color:#EDF5FF;font-weight:780}
.stButton>button,.stDownloadButton>button {border-radius:10px;min-height:52px;padding:0 16px;font-weight:700;border:1px solid #26364A;background:#111925;color:#DCE8F6;transition:all .15s ease}
.stButton>button[kind="primary"] {background:linear-gradient(110deg,#087BC7,#00A5C7);border:1px solid #18B6DC;color:#031019;box-shadow:0 6px 19px rgba(0,157,217,.2)}
.stButton>button:hover,.stDownloadButton>button:hover {border-color:#16BCE4;color:#fff;transform:translateY(-1px)}
[data-testid="stTabs"] [role="tab"] {font-weight:700;color:#8190A4;padding:12px 16px}
[data-testid="stTabs"] [aria-selected="true"] {color:#42C9F6}
[data-testid="stTabs"] [data-baseweb="tab-highlight"] {background:#20BFE8}
[data-testid="stFileUploader"] section {border-radius:13px;border-color:#2A394A;background:#0D131D}
[data-testid="stFileUploader"] small,[data-testid="stFileUploader"] label {color:#ABB9CB}
[data-testid="stDataFrame"] {border:1px solid #202C3B;border-radius:12px;overflow:hidden}
[data-testid="stTextArea"] textarea {background:#0C121B!important;color:#E2EAF4!important;border:1px solid #2A394A!important;border-radius:12px!important;line-height:1.65}
[data-testid="stTextArea"] textarea:focus {border-color:#19BCE5!important;box-shadow:0 0 0 1px #19BCE5!important}
[data-testid="stTextArea"] label,[data-testid="stSelectbox"] label {color:#C5D0DF!important}
[data-testid="stSelectbox"] [data-baseweb="select"] > div {background:#0C121B;border-color:#2A394A;color:#E2EAF4}
[data-testid="stSelectbox"] [data-baseweb="select"] svg {fill:#AFC0D3}
[role="listbox"] {background:#101823;border:1px solid #2A394A}
[role="option"] {color:#DCE6F3}
[role="option"]:hover {background:#17283A}
.safe-note {background:#0E1924;border:1px solid #24394C;border-radius:12px;padding:13px 15px;color:#A6B6CA;font-size:12px;line-height:1.65}
[data-testid="stAlert"] {background:#0F1924;color:#C2D2E4;border:1px solid #24394C}
@media (max-width:700px) {.hero{padding:20px;gap:16px}.hero-logo{width:72px;height:72px;flex-basis:72px}.hero h1{font-size:23px}}
</style>
""", unsafe_allow_html=True)


def render_highlight(text, entities):
    chunks, cursor = [], 0
    for entity in entities:
        start, end = entity["start"], entity["end"]
        if start < cursor or end > len(text) or start >= end:
            continue
        chunks.append(html.escape(text[cursor:start]))
        category = entity["category"]
        bg, fg = COLORS.get(category, ("#E2E8F0", "#334155"))
        chunks.append(
            f'<span class="entity-chip" style="background:{bg};color:{fg}">'
            f'{html.escape(text[start:end])}<sup>{html.escape(category.upper())}</sup></span>'
        )
        cursor = end
    chunks.append(html.escape(text[cursor:]))
    return "".join(chunks)


def analyze_and_store(text):
    if not text.strip():
        st.warning("Bạn hãy nhập nội dung tin nhắn trước.")
        return
    result = analyze_message(text)
    st.session_state["message_text"] = text
    st.session_state["message_result"] = result


def clear_message_input():
    st.session_state["message_input"] = ""


SAMPLE_MESSAGES = {scenario["title"]: scenario["sample"] for scenario in SCENARIOS}


st.markdown("""
<div class="hero">
  <img class="hero-logo" src="data:image/png;base64,{LOGO_DATA}" alt="FourT logo" />
  <div><div class="eyebrow">FOURT · CÔNG CỤ HỖ TRỢ AN TOÀN SỐ</div>
  <h1>Kiểm tra tin nhắn đáng ngờ</h1>
  <p>Phân tích nội dung để tìm số điện thoại, số tài khoản, tổ chức được nhắc đến và các dấu hiệu lừa đảo thường gặp. Kết quả được giải thích rõ để bạn chủ động xác minh.</p></div>
</div>
""".replace("{LOGO_DATA}", LOGO_DATA), unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## FOURT · AN TOÀN SỐ")
    st.caption("Công cụ sàng lọc ban đầu. Cảnh báo không khẳng định người gửi chắc chắn lừa đảo.")
    st.markdown("### Nhóm thông tin nhận diện")
    for category, (bg, fg) in COLORS.items():
        st.markdown(f'<span class="legend" style="background:{bg};color:{fg}">{category}</span>', unsafe_allow_html=True)
    st.markdown("---")
    st.markdown('<div class="safe-note"><b>Nguyên tắc an toàn</b><br>Không cung cấp OTP, không bấm liên kết và không gọi số trong tin nhắn. Hãy tự mở ứng dụng hoặc tìm kênh liên hệ chính thức.</div>', unsafe_allow_html=True)

input_tab, batch_tab, about_tab = st.tabs(["📩 Phân tích tin nhắn", "📄 Phân tích CSV", "ℹ️ Giới thiệu"])

with input_tab:
    st.markdown('<div class="section-title">Phân tích một tin nhắn</div><div class="section-subtitle">Dán nội dung SMS, email hoặc tin nhắn chat để kiểm tra các dấu hiệu đáng ngờ.</div>', unsafe_allow_html=True)
    st.caption("Hệ thống đối chiếu với thư viện tình huống bằng ngữ nghĩa và từ/cụm từ. Lần đầu có thể cần tải mô hình về máy.")
    sample_col, hint_col = st.columns([2, 4])
    with sample_col:
        selected_sample = st.selectbox(
            "Chọn văn bản mẫu", list(SAMPLE_MESSAGES), label_visibility="collapsed",
            key="sample_choice",
        )
    with hint_col:
        if st.button("✦  Nạp văn bản mẫu", use_container_width=True):
            st.session_state["message_input"] = SAMPLE_MESSAGES[selected_sample]
            st.rerun()
    message = st.text_area(
        "Tin nhắn", key="message_input", height=170,
        placeholder="Dán nội dung SMS, email hoặc tin nhắn cần kiểm tra vào đây…",
        label_visibility="collapsed",
    )
    left, middle, right = st.columns(3, gap="medium")
    with left:
        run = st.button("⌕  Phân tích ngay", type="primary", use_container_width=True)
    with middle:
        st.button("⌫  Xóa văn bản", on_click=clear_message_input, use_container_width=True)
    with right:
        clear = st.button("Xóa kết quả", use_container_width=True)
    if run:
        with st.spinner("Đang trích xuất và đối chiếu với thư viện tình huống…"):
            analyze_and_store(message)
    if clear:
        st.session_state.pop("message_text", None)
        st.session_state.pop("message_result", None)
        st.rerun()

    result = st.session_state.get("message_result")
    text = st.session_state.get("message_text", "")
    if result and text:
        level = result["level"]
        risk_class = "risk-high" if level == "Cao" else "risk-medium" if level == "Cần thận trọng" else "risk-low"
        risk_icon = "⛔" if level == "Cao" else "⚠️" if level == "Cần thận trọng" else "✓"
        st.markdown(f'<div class="{risk_class}"><b>{risk_icon} &nbsp;MỨC CẢNH BÁO: {level.upper()}</b><br><span style="font-size:14px">Điểm sàng lọc <b>{result["score"]}/100</b> · Đây là kết quả tự động để tham khảo, không phải kết luận pháp lý.</span></div>', unsafe_allow_html=True)
        comparison = result.get("scenario_comparison", {})
        matches = comparison.get("matches", [])
        st.markdown('<div class="section-title">Đối chiếu với thư viện tình huống</div><div class="section-subtitle">Kết quả hiển thị mức độ gần với các ví dụ tham khảo; điểm tương đồng không phải xác suất lừa đảo.</div>', unsafe_allow_html=True)
        if matches:
            best = matches[0]
            st.markdown(
                f'**Tình huống gần nhất:** {html.escape(best["title"])} · '
                f'**{html.escape(best["label"])}** · '
                f'điểm tương đồng **{best["similarity"] * 100:.1f}/100**  \n'
                f'Phương pháp: {html.escape(comparison.get("method", ""))}',
            )
            with st.expander("Xem 3 tình huống đối chiếu và câu tham khảo"):
                for index, match in enumerate(matches, start=1):
                    st.markdown(f'**{index}. {match["title"]}** · {match["label"]} · {match["similarity"] * 100:.1f}/100')
                    st.caption(match["reference"])
            if not comparison.get("semantic_available"):
                st.caption("Mô hình ngữ nghĩa chưa sẵn sàng; đang dùng so khớp từ/cụm từ và ký tự làm phương án dự phòng.")
        else:
            st.info("Chưa có tình huống tham khảo phù hợp.")
        st.markdown('<div class="section-title">Nội dung và thực thể được phát hiện</div><div class="section-subtitle">Màu sắc biểu thị nhóm thông tin; nhãn nhỏ cho biết loại thực thể.</div>', unsafe_allow_html=True)
        st.markdown('<div class="result-card">' + render_highlight(text, result["entities"]) + '</div>', unsafe_allow_html=True)

        counts = {name: sum(1 for item in result["entities"] if item["category"] == name) for name in COLORS}
        cols = st.columns(6)
        cols[0].metric("Dấu hiệu rủi ro", len(result["signals"]))
        cols[1].metric("Số điện thoại", counts["Số điện thoại"])
        cols[2].metric("Số tài khoản", counts["Số tài khoản"])
        cols[3].metric("URL / đường dẫn", counts["Đường dẫn / URL"])
        cols[4].metric("Ngân hàng", counts["Ngân hàng"])
        cols[5].metric("Cơ quan / nhà mạng", counts["Cơ quan công an"] + counts["Nhà mạng"])

        st.markdown('<div class="section-title">Vì sao cần chú ý?</div><div class="section-subtitle">Các quy tắc đã khớp với nội dung tin nhắn.</div>', unsafe_allow_html=True)
        if result["signals"]:
            for signal in result["signals"]:
                st.markdown(f"- ⚠️ {signal}")
        else:
            st.success("Chưa phát hiện các dấu hiệu phổ biến trong bộ quy tắc hiện tại.")

        st.markdown('<div class="section-title">Thông tin trích xuất</div><div class="section-subtitle">Vị trí ký tự bắt đầu từ 0; đầu mút cuối không bao gồm.</div>', unsafe_allow_html=True)
        if result["entities"]:
            rows = [{"Thông tin gốc": e["text"], "Loại": e["category"], "Độ tin cậy quy tắc": e["score"], "Vị trí ký tự": f'{e["start"]}–{e["end"]}'} for e in result["entities"]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("Không tìm thấy URL, số điện thoại, số tài khoản hoặc tổ chức trong danh sách nhận diện.")
        best_match = matches[0] if matches else {}
        report = [{"Mức cảnh báo": level, "Điểm sàng lọc": result["score"], "Tình huống gần nhất": best_match.get("title", ""), "Nhãn tình huống gần nhất": best_match.get("label", ""), "Điểm tương đồng (không phải xác suất)": round(best_match.get("similarity", 0) * 100, 1), "Phương pháp đối chiếu": comparison.get("method", ""), "Dấu hiệu": "; ".join(result["signals"]), "Thông tin trích xuất": "; ".join(e["text"] for e in result["entities"])}]
        st.download_button("Tải báo cáo (.csv)", pd.DataFrame(report).to_csv(index=False).encode("utf-8-sig"), "bao_cao_tin_nhan.csv", "text/csv")
    else:
        st.info("Dán tin nhắn vào ô trên hoặc chọn **Điền tin nhắn mẫu**, sau đó bấm **Phân tích tin nhắn**.")

with batch_tab:
    st.markdown('<div class="section-title">Phân tích danh sách tin nhắn</div><div class="section-subtitle">Tải CSV lên, chọn cột chứa nội dung và nhận báo cáo cho toàn bộ dữ liệu.</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Chọn tệp CSV", type=["csv"])
    if uploaded:
        try:
            df = pd.read_csv(uploaded, encoding="utf-8-sig")
            if df.empty or not len(df.columns):
                st.warning("CSV chưa có dữ liệu.")
            else:
                st.dataframe(df.head(10), use_container_width=True, hide_index=True)
                column = st.selectbox("Cột chứa tin nhắn", df.columns.tolist())
                if st.button("Phân tích toàn bộ", type="primary"):
                    rows = []
                    progress = st.progress(0)
                    for i, value in enumerate(df[column]):
                        text = "" if pd.isna(value) else str(value)
                        result = analyze_message(text)
                        grouped = {name: [] for name in COLORS}
                        for entity in result["entities"]:
                            grouped[entity["category"]].append(entity["text"])
                        rows.append({
                            "Tin nhắn": text, "Mức cảnh báo": result["level"], "Điểm": result["score"],
                            "Số điện thoại": "; ".join(grouped["Số điện thoại"]),
                            "Số tài khoản": "; ".join(grouped["Số tài khoản"]),
                            "URL / đường dẫn": "; ".join(grouped["Đường dẫn / URL"]),
                            "Tổ chức": "; ".join(grouped["Ngân hàng"] + grouped["Cơ quan công an"] + grouped["Nhà mạng"]),
                            "Dấu hiệu": "; ".join(result["signals"]),
                            "Vị trí thực thể": "; ".join(f'{e["category"]}={e["start"]}:{e["end"]}' for e in result["entities"]),
                            "Tình huống tham khảo gần nhất": result.get("scenario_comparison", {}).get("matches", [{}])[0].get("title", ""),
                            "Nhãn tình huống gần nhất": result.get("scenario_comparison", {}).get("matches", [{}])[0].get("label", ""),
                            "Điểm tương đồng (không phải xác suất)": round(result.get("scenario_comparison", {}).get("matches", [{}])[0].get("similarity", 0) * 100, 1),
                        })
                        progress.progress((i + 1) / max(1, len(df)))
                    output = pd.DataFrame(rows)
                    st.dataframe(output, use_container_width=True, hide_index=True)
                    st.download_button("Tải kết quả CSV", output.to_csv(index=False).encode("utf-8-sig"), "phan_tich_tin_nhan.csv", "text/csv")
        except Exception as error:
            st.error("Không đọc được tệp CSV.")
            with st.expander("Chi tiết lỗi"):
                st.exception(error)

with about_tab:
    st.markdown('<div class="section-title">Minh bạch về kết quả</div><div class="section-subtitle">Công cụ sàng lọc hỗ trợ bạn phát hiện thông tin cần kiểm tra kỹ hơn.</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 01 · Trích xuất thông tin")
        st.write("Tìm URL, số điện thoại, số tài khoản trong ngữ cảnh giao dịch và tên ngân hàng, cơ quan công an, nhà mạng. Kết quả giữ nguyên nội dung gốc và vị trí để bạn đối chiếu.")
        st.markdown("#### 02 · Dò dấu hiệu rủi ro")
        st.write("Kiểm tra yêu cầu OTP/mật khẩu, chuyển tiền, thúc giục, đe dọa, liên kết, cài ứng dụng và yêu cầu giữ bí mật. Với URL, hệ thống xem xét tên miền IP, tên miền rút gọn, punycode, đuôi miền đáng ngờ, từ khóa đăng nhập/xác minh và dấu hiệu ghép tên tổ chức.")
    with c2:
        st.markdown("#### 03 · Tạo mức cảnh báo")
        st.write("Điểm kết hợp số dấu hiệu và mức đáng ngờ của URL cao nhất trong tin nhắn. Đây là điểm sàng lọc, không phải xác suất tin nhắn lừa đảo; có URL không đồng nghĩa với lừa đảo.")
        st.markdown("#### Giới hạn cần biết")
        st.write("Danh sách tổ chức và biến thể chữ có giới hạn; cách viết mới hoặc bị làm nhiễu mạnh có thể bị bỏ sót. Luôn xác minh qua ứng dụng, website hoặc tổng đài chính thức.")
    st.info("Không nhập thông tin cá nhân thật nếu không cần thiết. Không cung cấp OTP, bấm liên kết hay gọi số điện thoại được gửi trong tin nhắn đáng ngờ.")

st.markdown("<div style='text-align:center;color:#98A4B6;font-size:11px;margin-top:34px;padding-top:18px;border-top:1px solid #E5EAF2'>CÔNG CỤ HỖ TRỢ SÀNG LỌC · HÃY LUÔN XÁC MINH QUA KÊNH CHÍNH THỨC</div>", unsafe_allow_html=True)
