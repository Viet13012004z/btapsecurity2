import os
import re
import hashlib
import datetime
from datetime import timezone, timedelta

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_cert_from_pemder

# === Cấu hình đường dẫn ===
PDF_PATH = r"D:\btap2secu\signed.pdf"
CERT_PEM = r"D:\btap2secu\certificate.pem"
LOG_FILE = r"D:\btap2secu\check.txt"

# ================== HÀM PHỤ TRỢ ==================

def safe_print(msg: str):
    """In ra màn hình mà không lỗi font."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("utf-8", errors="ignore").decode("utf-8"))

def log(msg: str):
    """Ghi nội dung ra console và file log."""
    safe_print(msg)
    # Tạo thư mục log nếu chưa có
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def format_fp(fp):
    """Định dạng fingerprint cho dễ đọc."""
    if fp is None:
        return "N/A"
    if isinstance(fp, (bytes, bytearray)):
        h = fp.hex().upper()
    else:
        s = str(fp)
        h = re.sub(r"[^0-9A-Fa-f]", "", s).upper()
        if not h:
            return s
        h = s
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

def compute_sha256_range(pdf_bytes: bytes, byte_range):
    """Tính lại giá trị SHA256 dựa vào ByteRange trong chữ ký."""
    b = list(byte_range)
    data = pdf_bytes[b[0]:b[0]+b[1]] + pdf_bytes[b[2]:b[2]+b[3]]
    return hashlib.sha256(data).hexdigest()

def try_validation(sig_obj, trust_ctx):
    """
    Thử gọi validate_pdf_signature theo nhiều kiểu để tránh lỗi không tương thích.
    Trả về (status, error_message).
    """
    attempts = [
        ("vc", {"vc": trust_ctx}),
        ("validation_context", {"validation_context": trust_ctx}),
        ("positional", (trust_ctx,)),
        ("none", {})
    ]
    last_err = None
    for name, params in attempts:
        try:
            if name == "positional":
                result = validation.validate_pdf_signature(sig_obj, *params)
            elif name == "none":
                result = validation.validate_pdf_signature(sig_obj)
            else:
                result = validation.validate_pdf_signature(sig_obj, **params)
            return result, None
        except TypeError as te:
            last_err = te
            continue
        except Exception as e:
            return None, f"Lỗi khi kiểm tra ({name}): {repr(e)}"
    return None, f"Tất cả các cách gọi đều lỗi. Ngoại lệ cuối: {repr(last_err)}"

def get_first_attr(obj, *names):
    """Lấy thuộc tính đầu tiên tồn tại trong danh sách tên."""
    if obj is None:
        return None
    for n in names:
        try:
            if hasattr(obj, n):
                return getattr(obj, n)
        except Exception:
            pass
        try:
            return obj[n]
        except Exception:
            pass
    return None

# ================== CHƯƠNG TRÌNH CHÍNH ==================

def main():
    # reset log file
    try:
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
    except Exception:
        pass

    log("=== NGUYEN HOANG VIET ===")
    log(f"TIME CHECK: {datetime.datetime.now()}")
    log(f"FILE: {PDF_PATH}")
    log("=" * 65)

    # chuẩn bị ngữ cảnh xác thực
    try:
        if os.path.exists(CERT_PEM):
            cert_root = load_cert_from_pemder(CERT_PEM)
            trust_ctx = ValidationContext(trust_roots=[cert_root], allow_fetching=True)
            log("- Đã nạp chứng thư gốc từ PEM thành công.")
        else:
            trust_ctx = ValidationContext(trust_roots=None, allow_fetching=True)
            log("Không tìm thấy file PEM tin cậy — cho phép lấy thông tin trực tuyến.")
    except Exception as e:
        log(f"Lỗi khi đọc chứng thư: {e}")
        trust_ctx = None

    if not os.path.exists(PDF_PATH):
        log(f"Không tồn tại file PDF tại: {PDF_PATH}")
        return

    try:
        with open(PDF_PATH, "rb") as fh:
            reader = PdfFileReader(fh)
            signatures = list(reader.embedded_signatures)
            if not signatures:
                log("Không phát hiện chữ ký nào trong tài liệu.")
                return

            sig = signatures[0]
            log(f"- Đã phát hiện vùng chữ ký: {sig.field_name or 'SignatureField'}")

            try:
                sig_obj = sig.sig_object
                br = sig_obj.get("/ByteRange")
                contents = sig_obj.get("/Contents")
                log(f"- ByteRange: {list(br) if br else 'Không có'}")
                log(f"- Dung lượng /Contents: {len(contents) if contents else 'N/A'} bytes")
            except Exception:
                log("⚠️ Không thể đọc /ByteRange hoặc /Contents từ chữ ký.")

            # tính lại hash SHA256
            fh.seek(0)
            full_pdf = fh.read()
            if br:
                hash_val = compute_sha256_range(full_pdf, br)
                log(f"- Hash SHA256 được tính lại: {hash_val}")
            else:
                log("Không có ByteRange, bỏ qua bước tính hash.")

            # xác thực với pyHanko
            log("- Bắt đầu xác minh chữ ký (thử nhiều cách tương thích)...")
            status, err = try_validation(sig, trust_ctx)
            if err:
                log(f" ⚠️ Lỗi khi xác thực: {err}")
            if status is None:
                log("❌ Không thể xác định trạng thái chữ ký (status=None).")
                return

            # chi tiết kết quả
            try:
                detail = status.pretty_print_details()
                log("\n----------- Thông tin chi tiết quá trình xác minh ----------")
                for line in detail.splitlines():
                    log("   " + line)
                log("----------------------------------------------\n")
            except Exception:
                pass

            # thông tin chứng thư người ký
            signer_cert = get_first_attr(status, "signer_cert", "signing_cert", "signing_certificate")
            log("Thông tin về người ký:")
            if signer_cert is not None:
                subject = get_first_attr(signer_cert, "subject")
                readable = getattr(subject, "human_friendly", str(subject))
                fp1 = get_first_attr(signer_cert, "sha1_fingerprint") or get_first_attr(signer_cert, "sha1")
                fp2 = get_first_attr(signer_cert, "sha256_fingerprint") or get_first_attr(signer_cert, "sha256")
                log(f"   - Tên chủ thể: {readable}")
                log(f"   - SHA1 Fingerprint: {format_fp(fp1)}")
                log(f"   - SHA256 Fingerprint: {format_fp(fp2)}")
            else:
                log("   ⚠️ Không thể trích xuất thông tin người ký.")

            # kiểm tra chuỗi chứng thư
            trusted = get_first_attr(status, "trusted")
            valid = get_first_attr(status, "valid")
            if trusted is True:
                log("- Chuỗi chứng thư: ✅ Được tin cậy hoàn toàn (đã xác minh CA).")
            elif valid:
                log("- Chuỗi chứng thư: ⚠️ Chữ ký hợp lệ nhưng chưa xác định CA gốc.")
            else:
                log("Chuỗi chứng thư: ❌ Không hợp lệ hoặc thiếu chứng thư xác minh.")

            # thông tin thu hồi (OCSP / CRL)
            rev_info = get_first_attr(status, "revinfo_validity") or get_first_attr(status, "revinfo_summary")
            if rev_info:
                log(f"- Tình trạng chứng thư (OCSP/CRL): {rev_info}")
            else:
                log("Không có dữ liệu OCSP hoặc CRL.")

            # thời gian ký
            signing_time = get_first_attr(status, "signing_time", "signer_reported_dt", "signer_time")
            if signing_time:
                tzvn = timezone(timedelta(hours=7))
                try:
                    vn_time = signing_time.astimezone(tzvn)
                    log(f"- Thời gian ký (UTC): {signing_time}  → Giờ VN: {vn_time}")
                except Exception:
                    log(f"- Thời gian ký: {signing_time}")
            else:
                log("Không tìm thấy dấu thời gian (timestamp).")

            # kiểm tra chỉnh sửa sau khi ký
            mod_level = get_first_attr(status, "modification_level")
            if mod_level == ModificationLevel.NONE:
                log("- Kiểm tra chỉnh sửa: ✅ Không có thay đổi nào sau khi ký.")
            elif mod_level == ModificationLevel.FORM_FILLING:
                log("Kiểm tra chỉnh sửa: ⚠️ Có điền form sau khi ký.")
            else:
                log("- Kiểm tra chỉnh sửa: ❌ File có thay đổi sau khi ký hoặc không xác định rõ.")

            # tổng kết
            log("\n=== KẾT LUẬN CHUNG ===")
            if valid:
                log("Kết quả: CHỮ KÝ HỢP LỆ — FILE VẪN NGUYÊN VẸN.")
            else:
                log("Kết quả: CHỮ KÝ KHÔNG HỢP LỆ HOẶC FILE ĐÃ BỊ CAN THIỆP.")

    except Exception as e:
        log(f"Lỗi trong quá trình xử lý PDF: {e}")

    log(f"\nQuá trình hoàn tất. Báo cáo được lưu tại: {os.path.abspath(LOG_FILE)}")

if __name__ == "__main__":
    main()
