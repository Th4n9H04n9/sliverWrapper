# sliverWrapper.cpp – Công cụ học tập / Red Teaming Lab

## Giới thiệu

`sliverWrapper.cpp` là một **trình tải shellcode (loader) viết bằng C++ cho Windows** hỗ trợ tải xuống, giải mã và thực thi shellcode trực tiếp trong bộ nhớ từ máy chủ C2.  
Công cụ này có thể dùng với **shellcode từ Sliver** hoặc **bất kỳ shellcode stage nào khác** lấy từ C2 trong môi trường lab.  
Ngoài ra, dự án còn cung cấp các hàm tiện ích để mã hóa/giải mã file (AES-128-CBC), tải file qua HTTP(S), và tùy chọn tự sao chép vào thư mục Startup để kiểm thử persistence.

> Mục tiêu của dự án là phục vụ việc học tập, nghiên cứu, và thực hành an toàn thông tin — đặc biệt là các bài lab mô phỏng kịch bản Red Team / Pentest.  
> Mình ý thức rằng chủ đề này nhạy cảm, nên tài liệu chỉ mô tả luồng kiểm thử ở **mức khái quát**, tránh chi tiết có thể gây hiểu lầm hoặc lạm dụng.

---

## Tuyên bố miễn trừ

> **Chỉ sử dụng cho mục đích học tập và nghiên cứu hợp pháp.**
>
> - Chỉ chạy trong môi trường lab cá nhân hoặc hệ thống đã được ủy quyền.
> - Không sử dụng trên môi trường sản xuất hoặc hệ thống không thuộc quyền kiểm soát.
> - Tác giả không chịu trách nhiệm đối với mọi hành vi lạm dụng hoặc vi phạm pháp luật.

---

## Tính năng

- Tải xuống shellcode đã mã hóa từ máy chủ C2 qua HTTP/HTTPS (có thể cấu hình proxy).
- Giải mã AES-128-CBC và thực thi shellcode trong bộ nhớ (fileless).
- Công cụ mã hóa/giải mã file để chuẩn bị payload trong lab.
- Tùy chọn tự sao chép vào thư mục Startup để **kiểm thử** persistence trong VM dùng một lần.
- Có thể tắt toàn bộ log/printf để hạn chế dấu vết trong thử nghiệm.

---

## Trường hợp sử dụng

- **Lab Red Team / Pentest:** Kiểm thử kỹ thuật tải và thực thi shellcode trong bộ nhớ.
- **Luyện thi chứng chỉ:** OSCP, CRTO, CRTP,… nơi cần tự phát triển loader và thử nghiệm bypass AV/EDR trong lab.
- **Nghiên cứu malware:** Tìm hiểu cơ chế của dropper và fileless malware trong môi trường kiểm soát.

---

## Biên dịch (MinGW/MSYS2)

Biên dịch dạng tĩnh (không cần DLL OpenSSL):

```sh
g++ sliverWrapper.cpp -o sliverWrapper.exe -lwininet -lssl -lcrypto -lws2_32 -lcrypt32 -static -static-libgcc -static-libstdc++
```

- `-lwininet`    : Windows HTTP(S) API  
- `-lssl -lcrypto`: Thư viện OpenSSL (AES)  
- `-lws2_32`     : Windows Sockets (cần cho OpenSSL)  
- `-lcrypt32`    : Windows CryptoAPI (cần cho OpenSSL)  
- `-static ...`  : Build tĩnh, không cần DLL ngoài  

> Cần có OpenSSL dạng static (`libssl.a`, `libcrypto.a`) trong MSYS2.  
> Nếu báo lỗi thiếu symbol OpenSSL, kiểm tra lại cài đặt thư viện.

---

## Cách dùng (mô tả cấp cao trong lab hợp pháp)

> Phần này chỉ mô tả **luồng thao tác tổng quát** để kiểm thử trong lab. Vui lòng **không** áp dụng ngoài phạm vi được ủy quyền.

### 1) Chuẩn bị “stage shellcode” an toàn để kiểm thử
- Tạo stage **vô hại** (ví dụ: hiển thị hộp thoại, ghi log cục bộ) nhằm quan sát luồng nạp/thực thi.  
- Có thể dùng shellcode từ **Sliver** hoặc **bất kỳ stage C2** nào khác, miễn là chỉ chạy trong lab.

### 2) Mã hóa stage trước khi phân phối
- Dùng tiện ích đi kèm dự án để **mã hóa nhị phân stage** bằng AES-128-CBC (khóa/IV tự quản lý trong lab).  
- Mục tiêu là thu được “ciphertext” (ví dụ `stage.bin.enc`) để loader có thể tải và giải mã khi chạy thử nghiệm.

> Gợi ý an toàn: Quản lý khóa/IV tách biệt với nơi lưu ciphertext; không commit khóa/IV vào repo; thay đổi định kỳ trong lab.

### 3) Đặt “ciphertext” ở điểm phát trong lab
- Lưu `stage.bin.enc` tại một **điểm phát trong lab** (thư mục chia sẻ nội bộ hoặc endpoint HTTP nội bộ).  
- Hoặc lưu ở **đường dẫn tạm** trong VM để mô phỏng “tải-xuống-rồi-chạy” mà không rời lab.

### 4) Cấu hình loader cho nguồn lấy stage
- Cập nhật tham số máy chủ/đường dẫn trong mã nguồn:
  ```cpp
  std::wstring host = L"LAB_SERVER_OR_IP";
  std::wstring path = L"/path/to/stage.bin.enc";
  ```
- Nếu lab dùng proxy, bật cấu hình proxy ở mức phù hợp (nội bộ).

### 5) Thực thi và quan sát
- Chạy loader trong **VM dùng một lần** (snapshot trước).  
- Loader sẽ tải ciphertext, giải mã trong bộ nhớ và nạp stage để thực thi.  
- Dùng công cụ quan sát (ETW, Sysmon/Windows Event Log, ProcMon) để theo dõi hành vi tiến trình, bộ nhớ, và I/O.

### 6) (Tùy chọn) Thử nghiệm persistence trong VM dùng một lần
- Nếu muốn đánh giá cơ chế tự sao chép vào Startup:  
  - Thực hiện **chỉ trong VM disposable** và **không** nối mạng Internet.  
  - Khởi động lại VM để xác nhận hành vi và xóa VM sau kiểm thử.

---

## Gỡ rối & xác minh (khái quát)

- **Tải xuống:** Kiểm tra log HTTP(S) trong lab để chắc chắn endpoint trả về đúng “ciphertext”.  
- **Giải mã:** Xác nhận khóa/IV đúng và kích thước dữ liệu hợp lệ (đồng bộ padding/IV giữa tiện ích mã hóa và loader).  
- **Thực thi trong bộ nhớ:** Nếu stage không chạy, xem lại quyền trang nhớ, căn chỉnh stack, và calling convention của **stage test vô hại**.  
- **EDR/AV trong lab:** Nếu VM bật giải pháp bảo vệ, ghi nhận alert/telemetry để học cách phòng thủ; tránh tìm cách né tránh ngoài phạm vi lab.

---

## Lưu ý quan trọng

- AV/EDR có thể sẽ chặn hoặc cảnh báo — đây là điều bình thường khi mô phỏng tình huống tấn công.  
- Chỉ chạy trên hệ thống thuộc quyền quản lý hoặc được cấp phép.  
- Không triển khai persistence ngoài VM disposable.  
- Tắt log chỉ nhằm giảm nhiễu trong thử nghiệm; **không** nhằm mục đích che giấu hành vi trái phép.

---

## Giấy phép

Cung cấp **nguyên trạng** cho mục đích học tập.  
Không bảo hành, không hỗ trợ, sử dụng tự chịu trách nhiệm.
