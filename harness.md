# Harness Agent — ProofHound

## نظرة عامة
ProofHound نظام فحص آلي للكود يكتشف الأنماط المسببة للأخطاء باستخدام البحث العميق في قاعدة الكود (grep/ast) ثم تنفيذ اختبارات سريعة للتحقق.

## هيكل المشروع
- **frontend**: React + TypeScript (مبني بـ esbuild، بدون bundler)
- **core**: Python CLI يحتوي منطق الفحص
- **tests**: اختبارات pytest مع بيانات تجريبية

## قواعد العمل
1. ابحث بـ grep أولاً قبل أي اقتراح
2. أي تعديل على core يتطلب تشغيل `pytest` للتحقق
3. أي تعديل على frontend يتطلب `npx esbuild src/index.tsx --outfile=dist/bundle.js --loader:.tsx=tsx`
4. لا تبحث أكثر من جولتين — إذا لم تجد، أشر إلى ذلك بوضوح
5. استخدم tools الذكاء الاصطناعي بدل التخمين

## الأنماط المكتشفة
- asyncio.gather بدون return_exceptions=True مع try/except خارجي
- subprocess.run(check=False) أو subprocess.Popen بدون returncode
- yaml.load() بدون Loader
- async calls داخل sync context

## التحقق قبل الإدعاء
- ضع مثال مضاد سريع (30 ثانية كحد أقصى)
- نفّذه وتأكد من النتيجة قبل الإبلاغ عن خطأ
- المعلومات العامة لا تغني عن التحقق من الكود الفعلي

## التزامن
- اتبع نمط الكود الموجود (async/await في core، JSX في frontend)
- لا تكتب تعليقات إلا إذا طُلب منك
- الملفات الجديدة توضع في المجلد المناسب حسب اللغة
