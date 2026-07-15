# شرح الأمثلة بالعربية

كل الأمثلة اصطناعية ودفاعية ولا تحتوي على exploit payloads.

## 1. وكيل تذاكر الدعم

الملف: `examples/example-inventory.json`

يستخدم الوكيل حالة مقترحة اشتقها النموذج من تعليق خارجي لإغلاق التذكرة. لا
تحتفظ القيمة المشتقة بسلسلة مصدرها، كما أن الموافقة البشرية مبنية على تفسير
الوكيل نفسه.

النتائج الأساسية المتوقعة:

- ADIP-04 بسبب mixed-trust object بلا عزل؛
- ADIP-06 بسبب فقدان provenance للقيمة المشتقة؛
- ADIP-03 لأن Action Parameter غير متحقق منه بالكامل؛
- ADIP-05 لأن الموافقة ليست من قناة مستقلة.

## 2. وكيل البريد

### قبل المعالجة

`examples/email-agent/before.json`

يستخدم الوكيل `display_sender` المتأثر بمحتوى الرسالة كمصدر موثوق وكمستلم
للرد. يجمع الكائن بين metadata موثوقة ونص خارجي بلا structural isolation.

### بعد المعالجة

`examples/email-agent/after.json`

- يحصل الوكيل على `sender_address` من authenticated backend envelope؛
- يسجل دليل اختبار العزل البنيوي؛
- يتحقق من صيغة العنوان ومن مصدره؛
- يعرض للمراجع البشري قيمة مصدرها backend مستقل؛
- يربط mitigation باختبار integration قابل للمراجعة.

```bash
monna-adip examples/email-agent/after.json --validate --format text
```

النتيجة المتوقعة: `REVIEW_READY` بلا baseline findings.

## 3. وكيل مراجعة الكود

### قبل المعالجة

`examples/code-agent/before.json`

يتعامل الوكيل مع commit SHA مذكور داخل وصف Pull Request غير الموثوق كأنه
نتيجة تحقق، ثم يستخدمه في Merge Action حرجة.

### بعد المعالجة

`examples/code-agent/after.json`

- يفصل وصف PR غير الموثوق عن metadata المستودع؛
- يعيد جلب `head_commit_sha` من repository backend؛
- يتحقق من الصيغة ومن أن SHA هو الرأس الحالي؛
- يربط الحماية باختبارات integration وprotected-branch policy.

```bash
monna-adip examples/code-agent/after.json --validate --format markdown
```

النتيجة المتوقعة: `REVIEW_READY` بلا baseline findings.

## ملاحظة مهمة

معرّفات الأدلة داخل الأمثلة مثل `integration-suite/merge-31` توضيحية. يجب على
كل فريق استبدالها بأدلة حقيقية من نظامه، وإلا يصبح الادعاء بالحماية غير قابل
للمراجعة وقد يستحق ADIP-07.
