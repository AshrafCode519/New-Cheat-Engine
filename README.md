# New-Cheat-Engine (NCE)

محرك حديث عابر للمنصات (Cross-Platform) لفحص وتعديل الذاكرة، مصمم وفق معايير هندسية متقدمة ليكون بديلاً خفيفاً وعالي الكفاءة لبرامج فحص الذاكرة التقليدية.

---

## 🏛 المعمارية والمكونات الحالية

1. **`target_dummy` (الهدف التجريبي المعياري):**
   * عملية اختبار تفاعلية توفر بنية ذاكرة محددة بدقة (Known Values):
     * أعداد صحيحة 32-bit و 64-bit (`health`, `gold`).
     * أعداد حقيقية Float و Double (`mana`, `speed`).
     * نصوص ASCII (`player_name`).
     * هياكل بيانات مجمعة (Grouped Structs) لاختبار فحص القيم المتجاورة (`PlayerStats`).
     * قيم مشفرة بنظام XOR (`ObfuscatedValue`).
     * سلاسل مؤشرات متعددة المستويات (Multi-level Pointers: Base -> L1 -> L2 -> L3 -> Target).
     * وضع محاكاة التغيرات التلقائية (Auto-Decay) لاختبار Next Scan.

2. **`engine` (نواة المحرك):**
   * **طبقة تجريد النظام (HAL):**
     * واجهة `IProcess` للتعامل الشفاف مع أنظمة التشغيل (Windows حالياً مع جاهزية التوسيع لـ Linux).
     * فحص ذكي لصفحات الذاكرة عبر `VirtualQueryEx` مع استبعاد صفحات الـ Guard و NoAccess.
     * كتابة آمنة على الذاكرة مع إدارة الصلاحيات تلقائياً (`VirtualProtectEx`).
     * تجميد واستئناف العمليات الهدف (`NtSuspendProcess` / `NtResumeProcess`) لمنع القراءات الممزقة (Torn Reads).
     * استخراج وتصنيف وحدات البرنامج (Modules) لحساب قواعد المؤشرات (Base Offsets).
   * **محرك الفحص المتوازي (MemoryScanner):**
     * فحص متوازي متعدد الخيوط (Multithreaded Chunk Scanning).
     * دعم مختلف أنواع البيانات (`Int8`, `Int16`, `Int32`, `Int64`, `Float`, `Double`, `AOB`).
     * بحث متقدم عن أنماط البايتات مع الرموز البديلة (`AOB Scan with '?' wildcards`).
     * فحص ترشيحي متسلسل (Next Scan): `Exact`, `Changed`, `Unchanged`, `Increased`, `Decreased`.
   * **الفحص المجمع (Grouped Scanner):**
     * البحث عن متغيرات متعددة تقع متجاورة ضمن نفس الـ Struct في نافذة ذاكرة محددة (مثل `health` و `mana` و `armor` ضمن 256 بايت).
     * يقلص النتائج العشوائية الخاطئة بنسبة 99.9% في فحص واحد.
   * **فاحص المؤشرات (Pointer Scanner & Pointer Map):**
     * بناء خريطة مؤشرات مفهرسة ومرتبة بالـ Binary Search.
     * خوارزمية بحث عكسي (Reverse BFS) من العنوان الهدف إلى قواعد الـ Modules الثابتة.
     * استخراج سلاسل المؤشرات بهيئة `[module.exe + offset] -> [offset1] -> [offset2]`.
   * **محرك التجميد التلقائي (Freeze Engine):**
     * خيط خلفي عالي التردد (100ms) لقفل وتثبيت القيم في الذاكرة دون انقطاع.

3. **`memscan_cli` (أداة سطر الأوامر التفاعلية):**
   * عرض العمليات الحية والبحث بالاسم (`ps`).
   * الاتصال بالعملية (`attach <pid>`).
   * فحص الذاكرة وتصفية النتائج (`scan`, `next`, `list`).
   * الفحص المجمع (`group i32 100 i32 50 f32 25.5`).
   * فحص سلاسل المؤشرات (`ptrscan <addr> [depth] [offset]`).
   * قراءة وكتابة وتعديل قيم الذاكرة الحية (`read`, `write`).
   * تجميد وإلغاء تجميد القيم (`freeze`, `frozen`, `unfreeze`).
   * استعراض الذاكرة بتنسيق Hex Dump (`dump <addr> [bytes]`).

---

## 🚀 كيفية البناء والتشغيل

### البناء (CMake + MinGW / C++20):
```powershell
cmake -B build -G "MinGW Makefiles"
cmake --build build
```

### التشغيل والاختبار:
1. قم بتشغيل الهدف التجريبي:
```powershell
.\build\bin\target_dummy.exe
```
2. في نافذة أخرى، شغل أداة الفحص:
```powershell
.\build\bin\memscan_cli.exe
```
3. داخل أداة الفحص:
```text
attach <PID_المعروض_في_الهدف>
scan i32 1337
list
write <العنوان_المكتشف> i32 99999
```
ستلاحظ تغير قيمة الصحة فوراً داخل البرنامج الهدف.

