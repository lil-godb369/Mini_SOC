# Phạm vi detection và bằng chứng kiểm thử

Đợt tinh chỉnh rule ngày 2026-11-10. Rule engine hiện có **7 rule**, tách
scheduled task và cron khỏi Registry Run key. Heuristic ransomware là detector
riêng. Rule matching không chứng minh lệnh đã thực thi thành công hay là độc hại.

## Hợp đồng hiện tại

| Rule / MITRE | Điều kiện chính | Ca âm quan trọng / giới hạn |
|---|---|---|
| T1059.001 PowerShell | process powershell/pwsh và encoded command, hidden hoặc mẫu tải/thực thi | NoProfile/Bypass đơn lẻ không đủ; không quan sát PowerShell nhúng/in-process |
| T1003 Credential Dumping | tên công cụ phù hợp và mẫu dump LSASS/credential hoặc đọc shadow | procdump help/dump notepad, tài liệu nhắc lsass không báo; tên công cụ đổi có thể bị bỏ sót |
| T1547.001 Run key | reg add vào CurrentVersion Run/RunOnce, có /d | reg query/help/ghi key khác không báo; chưa có Set-ItemProperty/registry callback |
| T1053.005 Scheduled Task | schtasks /create có /tr | /query, /create /? không báo; PowerShell cmdlet/GUI chưa được bao phủ |
| T1053.003 Cron | process crontab cài file hoặc stdin | -l/-r không báo; chưa hỗ trợ -u, redirect thẳng vào cron hoặc shell profile |
| T1057 Process Discovery | 4 discovery event cùng host/PPID trong 15s, event kích hoạt phải là tasklist/ps | whoami/ipconfig đơn thuần không được gắn T1057; vẫn có thể là quản trị hợp lệ |
| T1486 file burst | 12 file_modify event cùng host trong 5s | **Medium**, chưa xác nhận mã hóa; build/backup cũng có thể khớp; đếm event, không phải file duy nhất |

Rule discovery giữ các lệnh do thám khác làm ngữ cảnh, nhưng chỉ phát cảnh báo
T1057 khi có event tasklist/ps vượt ngưỡng. Nếu process enumeration xảy ra trước
các event khác và không lặp lại khi đạt ngưỡng thì có thể bỏ sót. Đây là lựa
chọn trigger đơn giản, không phải ánh xạ toàn bộ hoạt động discovery vào T1057.

Đổi severity file-burst từ Critical sang Medium để phản ánh bằng chứng hiện có.
Heuristic ransomware vẫn tự chấm severity từ entropy/tốc độ/đuôi/độ lan. Không
hiểu điểm heuristic là xác suất nhiễm; hai nguồn alert vẫn có thể cùng xuất hiện.
Không thay severity hoặc mapping của alert lịch sử đã lưu.

## Kiểm thử và cách tái lập

`backend/tests/test_detection_contract.py` có 22 fixture luật đơn (9 ca dương,
13 ca âm), mỗi ca đi qua ingest → worker → DB → API alert và kiểm tra evidence.
Có thêm ca trigger discovery và ca ghi 12 file văn bản bình thường: rule burst
vẫn báo, heuristic không báo. Giữ ca này để công khai hạn chế, không che báo nhầm.

Các fixture được chọn có chủ đích để khóa hợp đồng. Không dùng tỷ lệ đúng trên
22 mẫu này như precision/recall/FPR của sản phẩm. Chưa có corpus đại diện tác
vụ backup/build/giải nén hay tập ransomware thực để hiệu chỉnh ngưỡng thực nghiệm.

Chạy pytest bằng lệnh trong [kế hoạch](KE-HOACH-HOAN-THIEN.md).
Kết quả đợt này: **210 passed** trên Python 3.9; Docker PG/Redis riêng **PASS**.
Kiểm thử PG/Redis thật có thêm ca dương/âm PowerShell, Run key, scheduled task,
cron và credential, kiểm tra mapping/evidence qua API; xem
[tests/integration](../tests/integration/README.md).

## Mô phỏng và giới hạn endpoint

`persistence_sim.py` mặc định chỉ in lệnh, không sinh reg add thật và không
kỳ vọng alert. Không gọi help hoặc echo rồi coi đó là tạo persistence.
`--for-real` thay đổi máy và phải có bước hoàn tác; đợt này KHÔNG chạy chế độ đó.
Linux demo ghi shell profile chưa được rule hiện tại bao phủ.

`discovery.py` chạy lệnh chỉ đọc, nhưng tiến trình sống ngắn có thể lọt giữa
hai lần polling. Các test fixture không chứng minh agent Windows thu được đủ
event. Chưa kiểm chứng lại collector live/persistence thật trong đợt này.

## Nguồn MITRE đã đối chiếu

- [PowerShell T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [OS Credential Dumping T1003](https://attack.mitre.org/techniques/T1003/)
- [Registry Run Keys / Startup Folder T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Scheduled Task T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [Cron T1053.003](https://attack.mitre.org/techniques/T1053/003/)
- [Process Discovery T1057](https://attack.mitre.org/techniques/T1057/)
- [Data Encrypted for Impact T1486](https://attack.mitre.org/techniques/T1486/)
