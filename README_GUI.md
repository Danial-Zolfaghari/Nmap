# Nmap Wrapper GUI - راهنمای کامل استفاده

## 📋 فهرست مطالب
- [نصب](#نصب)
- [ویژگی‌ها](#ویژگی‌ها)
- [استفاده](#استفاده)
- [راهنمای کامل تب‌ها](#راهنمای-کامل-تب‌ها)
- [نکات مهم](#نکات-مهم)
- [مشکلات احتمالی](#مشکلات-احتمالی)

## نصب

### 1. نصب PyQt6

```bash
pip install PyQt6
```

### 2. اجرای GUI

```bash
python nmap_wrapper_gui.py
```

## ویژگی‌ها

### ✨ ویژگی‌های اصلی
- **رابط کاربری گرافیکی کامل** با PyQt6
- **پشتیبانی از تمام گزینه‌های Nmap** (100% coverage)
- **Tooltip برای همه گزینه‌ها** - با hover روی هر گزینه توضیح مختصر نمایش داده می‌شود
- **تب Help & Guide** - راهنمای کامل با توضیحات دسته‌بندی‌شده
- **Real-time Output** - نمایش خروجی اسکن به صورت زنده
- **Progress Bar** - نمایش پیشرفت اسکن
- **ذخیره/لود Configuration** - امکان ذخیره و بارگذاری تنظیمات
- **Scan Profiles** - پروفایل‌های از پیش تعریف شده
- **Hall of Fame Scans** - اسکن‌های معروف از فیلم‌ها و pentest‌های واقعی

## راهنمای کامل تب‌ها

### 📌 تب Quick Scan
تب سریع برای اسکن‌های معمولی با گزینه‌های پرکاربرد.

#### Target Specification
- **Target(s)**: وارد کردن target (IP، hostname، CIDR، یا لیست جدا شده با کاما)
- **Validate**: اعتبارسنجی target قبل از اسکن

#### Quick Options
- **SYN Scan (-sS)**: اسکن SYN (پیش‌فرض، سریع، stealthy)
- **Version Detection (-sV)**: تشخیص نسخه سرویس‌ها
- **Default Scripts (-sC)**: اجرای اسکریپت‌های پیش‌فرض NSE
- **OS Detection (-O)**: تشخیص سیستم عامل

#### Port Specification
- **Ports**: تعیین پورت‌های خاص (مثال: `22,80,443` یا `1-1000`)
- **Fast Scan (Top 100)**: اسکن سریع 100 پورت پرکاربرد
- **Top Ports**: اسکن N پورت پرکاربرد
- **Exclude Ports**: حذف پورت‌های خاص از اسکن
- **Sequential (-r)**: اسکن ترتیبی پورت‌ها (بدون تصادفی‌سازی)

#### Timing
- **Timing Template**: انتخاب سطح timing (0=paranoid تا 5=insane)

### ⚙️ تب Advanced Options
تب پیشرفته با تمام گزینه‌های Nmap.

#### Target Specification (Advanced)
- **Input List (-iL)**: ورودی از فایل لیست hosts/networks
- **Random Targets (-iR)**: انتخاب تصادفی targetها
- **Exclude**: حذف hosts/networks (جدا شده با کاما)
- **Exclude File**: حذف از فایل

#### Host Discovery
- **List Scan (-sL)**: فقط لیست کردن targetها بدون اسکن
- **Ping Scan (-sn)**: فقط discovery، بدون port scan
- **Skip Discovery (-Pn)**: فرض کردن همه hosts آنلاین
- **TCP SYN/ACK/UDP/SCTP Discovery**: discovery با پروتکل‌های مختلف
- **ICMP Echo/Timestamp/Netmask**: discovery با ICMP
- **IP Protocol Ping (-PO)**: ping با IP protocol
- **No DNS Resolution (-n)**: عدم resolve کردن DNS
- **Always Resolve DNS (-R)**: همیشه resolve کردن DNS
- **DNS Servers**: تعیین DNS serverهای سفارشی
- **System DNS**: استفاده از DNS resolver سیستم عامل
- **Traceroute**: trace کردن مسیر به هر host

#### Scan Techniques
- **SYN Scan (-sS)**: اسکن SYN (stealth scan)
- **Connect Scan (-sT)**: اسکن Connect (بدون نیاز به root)
- **UDP Scan (-sU)**: اسکن UDP
- **Null Scan (-sN)**: اسکن Null (بدون flag)
- **FIN Scan (-sF)**: اسکن FIN
- **Xmas Scan (-sX)**: اسکن Xmas (FIN, PSH, URG)
- **Window Scan (-sW)**: اسکن Window
- **ACK Scan (-sA)**: اسکن ACK (برای map کردن firewall)
- **Maimon Scan (-sM)**: اسکن Maimon (FIN/ACK)
- **SCTP INIT Scan (-sY)**: اسکن SCTP INIT
- **SCTP Cookie Scan (-sZ)**: اسکن SCTP Cookie
- **IP Protocol Scan (-sO)**: اسکن IP protocol
- **Idle Scan (-sI)**: اسکن Idle با zombie host
- **Scan Flags**: تنظیم flagهای سفارشی TCP
- **FTP Bounce (-b)**: اسکن با FTP bounce

#### Port Specification
- **Ports**: تعیین پورت‌های خاص
- **Exclude Ports**: حذف پورت‌های خاص
- **Fast Scan (-F)**: اسکن سریع (top 100)
- **Sequential (-r)**: اسکن ترتیبی
- **Randomize Hosts**: تصادفی‌سازی ترتیب hosts
- **Top Ports**: اسکن N پورت پرکاربرد
- **Port Ratio**: اسکن پورت‌های با commonness بیشتر از ratio

#### Service/Version Detection
- **Version Detection (-sV)**: تشخیص نسخه سرویس
- **Version Intensity (0-9)**: شدت تشخیص نسخه
- **Version Light**: محدود به probeهای محتمل‌تر (intensity 2)
- **Version All**: امتحان همه probeها (intensity 9)
- **Version Trace**: نمایش جزئیات version scan

#### NSE Scripts
- **Default Scripts (-sC)**: اجرای اسکریپت‌های پیش‌فرض
- **Custom Scripts**: اجرای اسکریپت‌های خاص یا دسته‌ها (مثال: `vuln,exploit,auth`)
- **Script Args**: ارسال argument به اسکریپت‌ها (key=value pairs)
- **Script Args File**: ارسال argument از فایل
- **Script Trace**: نمایش تمام داده‌های ارسالی/دریافتی
- **Script Updatedb**: آپدیت database اسکریپت‌ها
- **Script Timeout**: تنظیم timeout برای اسکریپت‌ها
- **Lua Exec**: اجرای Lua script

#### OS Detection
- **OS Detection (-O)**: فعال‌سازی تشخیص OS
- **OS Scan Limit**: محدود کردن به targetهای promising
- **OS Scan Guess**: حدس زدن OS به صورت aggressive
- **Max OS Tries**: حداکثر تلاش برای تشخیص OS

#### Timing & Performance
- **Timing Template**: الگوی timing (0-5)
- **Min/Max Rate**: حداقل/حداکثر نرخ ارسال packet
- **Min/Max Hostgroup**: اندازه گروه hostهای موازی
- **Min/Max Parallelism**: موازی‌سازی probeها
- **Min/Max RTT Timeout**: timeout برای round trip time
- **Initial RTT Timeout**: timeout اولیه
- **Max Retries**: حداکثر retry
- **Host Timeout**: timeout برای هر host
- **Scan Delay**: تاخیر بین probeها
- **Max Scan Delay**: حداکثر تاخیر
- **Scan Delay Type**: نوع تاخیر (fixed یا random)
- **Port Ratio**: نسبت پورت‌های common
- **Defeat RST/ICMP Rate Limit**: شکستن rate limiting

#### Firewall/IDS Evasion & Spoofing
- **Fragment Packets (-f)**: fragment کردن packetها
- **MTU**: fragment با MTU مشخص
- **Decoys (-D)**: استفاده از decoy (RND:N یا IP list)
- **Spoof Source (-S)**: جعل آدرس مبدا
- **Interface (-e)**: استفاده از interface مشخص
- **Source Port (-g)**: استفاده از source port مشخص
- **Proxy**: استفاده از SOCKS5 proxy (مثال: `socks5://127.0.0.1:9050`)
- **Tor**: استفاده از Tor proxy
- **Data/Data String**: اضافه کردن payload سفارشی
- **Data Length**: اضافه کردن داده تصادفی
- **IP Options**: ارسال packet با IP options
- **TTL**: تنظیم time-to-live
- **Spoof MAC**: جعل MAC address
- **Bad Checksum**: ارسال packet با checksum نادرست
- **Randomize Hosts**: تصادفی‌سازی ترتیب hosts
- **Silent Mode**: حالت silent (بدون DNS، non-interactive)

#### Output Options
- **Output Normal (-oN)**: خروجی به فرمت normal
- **Output XML (-oX)**: خروجی به فرمت XML
- **Output All (-oA)**: خروجی به همه فرمت‌ها
- **Auto-generate filename**: تولید خودکار نام فایل با timestamp
- **Verbosity Level**: سطح verbosity (0-3)
- **Debug Level**: سطح debug (0-3)
- **Show Reason (--reason)**: نمایش دلیل state پورت
- **Open Ports Only (--open)**: فقط نمایش پورت‌های باز
- **Packet Trace (--packet-trace)**: نمایش تمام packetها
- **Interface List (--iflist)**: نمایش interfaceها و routeها
- **Append Output**: append کردن به فایل‌های خروجی
- **Resume**: ادامه اسکن از فایل
- **Resume Control**: ادامه با control file
- **Stylesheet**: XSL stylesheet برای XML
- **Web XML (--webxml)**: استفاده از stylesheet از Nmap.Org
- **No Stylesheet**: جلوگیری از association stylesheet
- **HTTP User-Agent**: تنظیم User-Agent string

#### Miscellaneous Options
- **IPv6 Scanning (-6)**: فعال‌سازی اسکن IPv6
- **Aggressive Scan (-A)**: فعال‌سازی OS detection، version detection، script scanning و traceroute
- **Data Directory**: تعیین دایرکتوری data سفارشی
- **Send Ethernet Frames (--send-eth)**: ارسال با ethernet frames
- **Send IP Packets (--send-ip)**: ارسال با IP packets
- **Privileged Mode (--privileged)**: فرض کردن privilege کامل
- **Unprivileged Mode (--unprivileged)**: فرض کردن عدم دسترسی raw socket

### 📚 تب Scan Profiles
انتخاب از پروفایل‌های از پیش تعریف شده برای اسکن‌های رایج.

#### Standard Profiles
- **full-scan**: اسکن کامل با تمام گزینه‌ها
- **stealth**: اسکن stealth با تکنیک‌های evasion
- **vuln-scan**: اسکن آسیب‌پذیری
- **firewall-evasion**: اسکن با evasion firewall
- **udp-heavy**: اسکن سنگین UDP
- **reconnaissance**: reconnaissance اولیه
- **ultimate-stealth**: اسکن stealth پیشرفته با تمام تکنیک‌ها

#### Hall of Fame Scans
- **Mr. Robot Season 1 Scan**: اسکن معروف از سریال Mr. Robot
- **Anonymous Typical Scan**: اسکن معمول Anonymous
- **L33T H4X0R Scan**: اسکن ترکیبی (Xmas + Null + FIN + badsum + decoys)
- **Red Team Initial Recon**: reconnaissance اولیه red team
- **Bug Bounty Quick Scan**: اسکن سریع bug bounty

#### Features
- **View Description**: مشاهده توضیحات هر پروفایل
- **Save Configuration**: ذخیره تنظیمات فعلی
- **Load Configuration**: بارگذاری تنظیمات ذخیره شده
- **Start Profile Scan**: اجرای اسکن با پروفایل انتخاب شده

### 📊 تب Output & Results
نمایش و مدیریت نتایج اسکن.

#### Features
- **Real-time Output**: نمایش خروجی اسکن به صورت زنده
- **Progress Bar**: نمایش پیشرفت اسکن
- **Clear Output**: پاک کردن خروجی
- **Save Output**: ذخیره خروجی در فایل
- **Auto-open XML**: باز کردن خودکار فایل XML در مرورگر (در صورت وجود)

### 📖 تب Help & Guide
راهنمای کامل با توضیحات دسته‌بندی‌شده برای تمام گزینه‌های Nmap.

#### Sections
- **Introduction**: معرفی و راهنمای شروع سریع
- **Target Specification**: توضیحات گزینه‌های target
- **Host Discovery**: توضیحات discovery methods
- **Scan Techniques**: توضیحات انواع اسکن
- **Port Specification**: توضیحات گزینه‌های port
- **Service/Version Detection**: توضیحات version detection
- **Script Scan (NSE)**: توضیحات NSE scripts
- **OS Detection**: توضیحات OS detection
- **Timing & Performance**: توضیحات timing options
- **Firewall/IDS Evasion**: توضیحات evasion techniques
- **Output**: توضیحات گزینه‌های خروجی
- **Miscellaneous**: توضیحات گزینه‌های متفرقه

## استفاده

### 1. Quick Scan
برای اسکن‌های سریع و معمولی:
1. به تب **Quick Scan** بروید
2. Target را وارد کنید (مثال: `192.168.1.1` یا `google.com`)
3. گزینه‌های مورد نظر را انتخاب کنید
4. روی **"Start Scan"** کلیک کنید
5. نتایج را در تب **Output & Results** مشاهده کنید

### 2. Advanced Scan
برای اسکن‌های پیشرفته با کنترل کامل:
1. به تب **Advanced Options** بروید
2. گزینه‌های مورد نظر را از بخش‌های مختلف تنظیم کنید
   - برای مشاهده توضیحات، روی هر گزینه hover کنید
3. Target را در تب **Quick Scan** وارد کنید
4. روی **"Start Advanced Scan"** کلیک کنید
5. نتایج را در تب **Output & Results** مشاهده کنید

### 3. Profile Scan
برای استفاده از پروفایل‌های از پیش تعریف شده:
1. به تب **Scan Profiles** بروید
2. یک پروفایل از لیست انتخاب کنید
3. توضیحات پروفایل را در بخش پایین مشاهده کنید
4. Target را وارد کنید
5. روی **"Start Profile Scan"** کلیک کنید

### 4. Save/Load Configuration
برای ذخیره و استفاده مجدد از تنظیمات:
1. تنظیمات مورد نظر را در تب **Advanced Options** یا **Quick Scan** تنظیم کنید
2. به تب **Scan Profiles** بروید
3. روی **"Save Current Configuration"** کلیک کنید
4. نام فایل را وارد و ذخیره کنید
5. برای بارگذاری، روی **"Load Saved Configuration"** کلیک کنید
6. فایل configuration را انتخاب کنید

### 5. استفاده از Help & Guide
برای یادگیری گزینه‌های Nmap:
1. به تب **Help & Guide** بروید
2. بخش مورد نظر را پیدا کنید
3. توضیحات کامل را مطالعه کنید
4. یا در تب **Advanced Options**، روی هر گزینه hover کنید تا tooltip را ببینید

## نکات مهم

### پیش‌نیازها
- فایل `nmap_wrapper copy.py` باید در همان دایرکتوری باشد
- **Nmap** باید نصب باشد و در PATH سیستم باشد
- **PyQt6** باید نصب باشد

### استفاده از Tor
برای استفاده از Tor:
1. مطمئن شوید Tor روی `127.0.0.1:9050` در حال اجرا است
2. در تب **Advanced Options**، بخش **Firewall/IDS Evasion**
3. گزینه **"Use Tor"** را فعال کنید
4. یا در فیلد **Proxy**، `socks5://127.0.0.1:9050` را وارد کنید

### Privilege Requirements
برخی اسکن‌ها نیاز به root/sudo دارند:
- **SYN Scan (-sS)**: نیاز به root
- **UDP Scan (-sU)**: نیاز به root
- **OS Detection (-O)**: نیاز به root
- **Null/FIN/Xmas Scans**: نیاز به root

برای اسکن بدون root، از **Connect Scan (-sT)** استفاده کنید.

### Silent Mode
**Silent Mode** به صورت پیش‌فرض فعال است:
- DNS resolution غیرفعال (`-n`)
- Non-interactive mode
- کاهش footprint شبکه

برای غیرفعال کردن، گزینه **"Silent Mode"** را در تب **Advanced Options** خاموش کنید.

### Auto-Output
با فعال کردن **"Auto-generate filename"**:
- نام فایل به صورت خودکار با timestamp و target name تولید می‌شود
- مثال: `scan_20251121_1430_google.com.xml`
- فایل XML به صورت خودکار در مرورگر باز می‌شود

## مشکلات احتمالی

### Import Error
اگر خطای import دریافت کردید:
```bash
pip install PyQt6
```

### Module Not Found
اگر `nmap_wrapper copy.py` پیدا نشد:
- مطمئن شوید فایل در همان دایرکتوری است
- نام فایل باید دقیقاً `nmap_wrapper copy.py` باشد
- یا مسیر را در خط 12 فایل `nmap_wrapper_gui.py` تغییر دهید:
  ```python
  wrapper_file = 'nmap_wrapper copy.py'  # مسیر را تغییر دهید
  ```

### Nmap Not Found
اگر خطای "nmap not found" دریافت کردید:
- مطمئن شوید Nmap نصب است
- در Windows، Nmap را به PATH اضافه کنید
- در Linux/Mac، از package manager نصب کنید:
  ```bash
  # Ubuntu/Debian
  sudo apt install nmap
  
  # macOS
  brew install nmap
  ```

### Permission Denied
اگر خطای permission دریافت کردید:
- برای اسکن‌های نیازمند root، از sudo استفاده کنید:
  ```bash
  sudo python nmap_wrapper_gui.py
  ```
- یا از **Unprivileged Mode** استفاده کنید

### GUI Not Responding
اگر GUI در حین اسکن freeze کرد:
- این طبیعی است برای اسکن‌های بزرگ
- از Progress Bar برای مشاهده پیشرفت استفاده کنید
- برای اسکن‌های بسیار بزرگ، از command line استفاده کنید

## مثال‌های استفاده

### مثال 1: اسکن سریع یک host
1. تب **Quick Scan**
2. Target: `192.168.1.1`
3. گزینه‌ها: SYN Scan، Version Detection
4. Start Scan

### مثال 2: اسکن stealth یک شبکه
1. تب **Scan Profiles**
2. انتخاب **"ultimate-stealth"**
3. Target: `192.168.1.0/24`
4. Start Profile Scan

### مثال 3: اسکن با Tor
1. تب **Advanced Options**
2. بخش **Firewall/IDS Evasion**
3. فعال کردن **"Use Tor"**
4. Target: `example.com`
5. Start Advanced Scan

### مثال 4: اسکن آسیب‌پذیری
1. تب **Advanced Options**
2. بخش **NSE Scripts**
3. Custom Scripts: `vuln`
4. Target: `192.168.1.1`
5. Start Advanced Scan

## پشتیبانی

برای مشکلات و سوالات:
- بررسی کنید که تمام پیش‌نیازها نصب هستند
- از تب **Help & Guide** برای یادگیری استفاده کنید
- Tooltipها را با hover روی گزینه‌ها بررسی کنید

---

**نسخه**: 1.0  
**آخرین به‌روزرسانی**: 2025

