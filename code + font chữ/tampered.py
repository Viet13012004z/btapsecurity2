import os
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from io import BytesIO

# ==== Cấu hình đường dẫn ====
PDF_INPUT = r"D:\btap2secu\pdf\signed.pdf"
PDF_OUTPUT = r"D:\btap2secu\code + font chữ\tampered.pdf"
FONT_PATH = r"D:\btap2secu\code + font chữ\DejaVuSans.ttf"  # font Unicode hỗ trợ tiếng Việt
HEADER_TEXT = "Helo tôi đã ddc thêm vào nè :D"

# ==== Đăng ký font Unicode ====
pdfmetrics.registerFont(TTFont('DejaVu', FONT_PATH))

# ==== Đọc PDF gốc ====
reader = PdfReader(PDF_INPUT)
writer = PdfWriter()

# ==== Chèn header lên trang đầu ====
first_page = reader.pages[0]

# Ép kiểu float để tránh lỗi Decimal
page_width = float(first_page.mediabox.width)
page_height = float(first_page.mediabox.height)

# Tạo overlay header
packet = BytesIO()
c = canvas.Canvas(packet, pagesize=(page_width, page_height))
c.setFont("DejaVu", 14)
c.setFillColorRGB(1, 0, 0)  # đỏ
y_offset = page_height - 50  # cách trên cùng ~50pt (~1,5 dòng)
c.drawString(50, y_offset, HEADER_TEXT)
c.save()

packet.seek(0)
overlay_pdf = PdfReader(packet)
overlay_page = overlay_pdf.pages[0]

# Merge overlay lên trang đầu
first_page.merge_page(overlay_page)
writer.add_page(first_page)

# Thêm các trang còn lại giữ nguyên
for page in reader.pages[1:]:
    writer.add_page(page)

# ==== Lưu PDF mới ====
with open(PDF_OUTPUT, "wb") as f_out:
    writer.write(f_out)

print(f"✅ PDF tampered đã được tạo tại: {PDF_OUTPUT}")
