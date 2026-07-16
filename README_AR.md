# MONNA ADIP™ — الدليل العربي

[English](README.md) | **العربية**

**بروتوكول سلامة بيانات الوكلاء**
Research Extension 01 · Open Core v0.3.0.dev0

MONNA ADIP هو إطار دفاعي وأداة سطر أوامر لاكتشاف فشل **حدود الثقة داخل
بيانات وكلاء الذكاء الاصطناعي**. يفحص استجابات الأدوات، والبيانات المسترجعة،
والبيانات الوصفية، وأدلة إجراءات الحماية، ومدخلات الأفعال على مستوى الحقول.

الهدف هو اكتشاف الحالات التي قد يفسّر فيها النموذج بيانات يستطيع المهاجم
التأثير فيها على أنها بيانات موثوقة صادرة عن النظام أو الأداة.

المشروع مستلهم بحثيًا من ورقة Choi وزملائه:
*Agent Data Injection Attacks are Realistic Threats to AI Agents*
(arXiv:2607.05120v1, 2026). وهو امتداد دفاعي مستقل من MONNA Consulting™،
وليس أداة رسمية تابعة للباحثين أو معتمدة منهم.

## المشكلة التي يعالجها

تركز أغلب دفاعات Prompt Injection على الفصل بين **التعليمات** و**البيانات**.
أما Agent Data Injection فيستغل حدًا مختلفًا: اختلاط البيانات الموثوقة وغير
الموثوقة داخل استجابة أداة أو كائن أو سجل سياق واحد.

قد يستمر الوكيل في تنفيذ هدف المستخدم الصحيح، لكنه ينفذ الفعل باستخدام:

- معرّف مورد مزيف؛
- عنوان أو مصدر غير موثوق؛
- نتيجة تحقق مختلقة؛
- سجل تنفيذ أدوات فُسّر بطريقة خاطئة؛
- قيمة مشتقة فقدت سلسلة مصدرها.

## الضوابط السبعة

1. رسم مصادر الثقة — Trust Origin Mapping
2. تصنيف الثقة على مستوى الحقول — Field-Level Trust Classification
3. اكتشاف تصادم حدود الثقة — Boundary Collision Detection
4. مراجعة الالتباس البنيوي — Structural Ambiguity Review
5. تتبع اعتماد القرارات على البيانات — Decision Dependency Tracing
6. بوابة سلامة الأفعال — Action Integrity Gate
7. ربط إجراءات الحماية بأدلة التحقق — Mitigation and Verification Mapping

اقرأ [المرجع العربي للإطار](docs/FRAMEWORK_AR.md) للاطلاع على شرح الضوابط
والنتائج ADIP-01 إلى ADIP-07.

## ما الجديد في v0.3؟

- سياق تهديد اختياري يضم آثار CIA ومسارات الهجوم ومراجع تصنيفات خارجية؛
- تتبع سلسلة المصدر عند تمرير البيانات بين نماذج متعددة؛
- فحص سلامة المخرجات قبل التنفيذ أو التخزين أو الإرسال أو تمريرها إلى نموذج آخر؛
- توسيع ADIP-05 ليشمل LLM Judge ومسارات التحقق غير المستقلة؛
- حفظ سياق التهديد داخل JSON وText وMarkdown وSARIF؛
- مثال آمن قبل/بعد لوكيل مراجعة متعدد النماذج.

راجع [دليل التوافق مع APE](docs/APE-COMPATIBILITY.md). هذا توافق مستقل يعتمد
على المعرّفات فقط ولا يعيد نشر التصنيف الخارجي أو يعدّ اكتشافًا للهجوم.

## ما الجديد في v0.2.0؟

- تنفيذ ADIP-07 لاكتشاف إجراءات الحماية التي لا تملك دليل تحقق؛
- تحقق اختياري من JSON Schema باستخدام `--validate`؛
- تقارير JSON وText وMarkdown وSARIF؛
- تحليل عدة ملفات أو مجلدات كاملة؛
- دعم `--version` و`--output` و`--recursive`؛
- اختبارات على Python 3.11 و3.12 و3.13؛
- أمثلة قبل/بعد لوكيل بريد ووكيل مراجعة كود؛
- Workflow آمن للنشر على PyPI باستخدام Trusted Publishing.

## التثبيت

يتطلب Python 3.11 أو أحدث.

```bash
python -m pip install -e .
```

لتفعيل التحقق الصارم من الـSchema:

```bash
python -m pip install -e ".[validation]"
```

يظل المحلل الأساسي بلا runtime dependencies. تُثبت حزمة `jsonschema` فقط عند
طلب ميزة `validation`.

## بداية سريعة

تقرير مختصر للبشر:

```bash
monna-adip examples/example-inventory.json --format text
```

التحقق من صحة الملف قبل التحليل:

```bash
monna-adip examples/example-inventory.json --validate --format text
```

تحليل مجلد كامل وإنتاج تقرير Markdown:

```bash
monna-adip examples --recursive --format markdown --output adip-report.md
```

إنشاء SARIF لرفعه إلى GitHub Code Scanning:

```bash
monna-adip inventories/ --format sarif --output adip.sarif
```

لشرح الأوامر ورموز الخروج بالعربية، راجع [البداية السريعة](docs/QUICKSTART_AR.md).

## الأمثلة

- [دليل الأمثلة بالعربية](docs/EXAMPLES_AR.md)
- [وكيل البريد: قبل وبعد](examples/email-agent/)
- [وكيل مراجعة الكود: قبل وبعد](examples/code-agent/)
- [وكيل متعدد النماذج: قبل وبعد](examples/multi-model-agent/)

كل الأمثلة اصطناعية ودفاعية ولا تحتوي على exploit payloads.

## قاعدة التوافق اللغوي

لا نترجم مفاتيح JSON أو القيم المعيارية داخل ملفات الـinventory. استخدم دائمًا:

```text
trusted | untrusted | derived | unknown
```

تُترجم المعاني والتوصيات في الوثائق فقط. هذا يحافظ على Schema واحدة وعلى
التوافق مع أدوات CI وSARIF والتكاملات المستقبلية.

راجع [قاموس المصطلحات العربي–الإنجليزي](docs/GLOSSARY_AR.md).

## حدود النسخة المفتوحة

يتضمن المستودع التصنيف العام، ونموذج الـinventory، وفحوص baseline، والأمثلة
الآمنة، وإرشادات الدمج. ولا يتضمن:

- معادلة MONNA التجارية لحساب المخاطر؛
- exploit corpus؛
- محرك الاختيار الآلي لإجراءات الحماية؛
- منطق تقارير العملاء؛
- تنفيذ SecurityFortress المحمي.

اقرأ [حدود الـOpen Core](docs/OPEN-CORE-BOUNDARY.md).

## الاستخدام المسؤول

المشروع دفاعي. لا ترسل علنًا exploit payloads أو تفاصيل ثغرات غير منشورة أو
أسرارًا أو بيانات عملاء. راجع [سياسة الأمان](SECURITY.md).

## الإسناد البحثي

Woohyuk Choi, Juhee Kim, Taehyun Kang, Jihyeon Jeong, Luyi Xing, and
Byoungyoung Lee. "Agent Data Injection Attacks are Realistic Threats to AI
Agents." arXiv:2607.05120v1, 2026.

- الورقة: https://arxiv.org/abs/2607.05120
- DOI: https://doi.org/10.48550/arXiv.2607.05120

الورقة منشورة بترخيص CC BY 4.0. هذا المستودع لا يعيد نشر أشكالها أو payloads
أو benchmark أو كود الباحثين.

## الترخيص والعلامات

المواد الأصلية في المستودع منشورة وفق Apache License 2.0. لا يمنح الترخيص حق
استخدام علامات MONNA أو MONNA ADIP أو SecurityFortress للترويج لأعمال مشتقة.
راجع [NOTICE](NOTICE).
