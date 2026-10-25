# خطة الوصول لـ 90-95% من كلود (Distillation v5)

**تاريخ البدء:** 2026-10-25
**الهدف النهائي:** النموذج المحلي يأكد ≥90% من الـ findings اللي كلود بيأكدها على نفس الـ benchmark
**الموعد النهائي للمناقشة:** ~2026-12-25 (شهرين)
**موعد نهاية Cloud credits:** 2026-11-05 (11 يوم) ⚠️

---

## 1. الوضع الحالي (Baseline)

### نتائج v4 على 12 حالة (108 finding)

| المرحلة | النتيجة | النسبة |
|---|---|---|
| Syntax OK | 94/108 | 87% |
| Loaded | 78/108 | 72% |
| Reached | 16/108 | 15% |
| **Crash Confirmed** | **4/108** | **3.7%** |

### الـ 4 ثغرات المؤكدة
1. `asset-cache_0.0.6` — path-traversal (ID: 029e512bac)
2. `asset-cache_0.0.6` — path-traversal (ID: a55ef60143)
3. `blamer_0.1.13` — command-injection (ID: 971e749caf)
4. `buns_1.1.6` — prototype-pollution (ID: 38c1722d51)

### التحليل حسب نوع الثغرة

| النوع | Total | Reached | Confirmed | ملاحظة |
|---|---|---|---|---|
| prototype-pollution | 9 | 56% | 11% | أعلى reach rate — الأمل الكبير |
| command-injection | 18 | 22% | 6% | متوسط |
| path-traversal | 24 | 12% | 8% | لما يوصل بيأكد كويس |
| **redos** | **57** | **7%** | **0%** | **مشكلة ضخمة — نصف الـ dataset** |

### الـ Bottleneck الحقيقي

- 87% بيكتب syntax سليم ✅
- 72% بيحمّل في Docker ✅
- **بس 15% بس بيوصل للـ sink** ← هنا الهاوية الحقيقية
- و 25% من اللي يوصل بيأكد الثغرة

**الاستنتاج:** المشكلة الرئيسية في `reach` (فهم الـ call chain وبناء الـ input)، مش في جودة الكود.

---

## 2. القيود والموارد

### القيود المالية والزمنية

| المورد | الحالة | الملاحظة |
|---|---|---|
| CodeCraft API (7 keys) | ❌ **نفد الـ quota** | يحتاج تجديد billing |
| Claude Code Cloud | ✅ $54 متبقّي | **يخلص Nov 5** (11 يوم) |
| Claude Pro subscription | ✅ Weekly 75% متبقّي | ينفع للـ orchestration |
| Kaggle GPU | ✅ 30h/أسبوع مجاناً | للـ training |
| RTX 4050 محلي | ✅ متاح | للـ inference والـ fuzzing |
| الوقت الكلي | 2 شهر | وقت كاف |

### الاستنتاج العملي

**المصدر الوحيد المتاح للـ distillation هو Claude Code Cloud ($54 يخلص في 11 يوم).**

ده بيحكم على استراتيجيتنا:
- محتاجين نستغل الـ $54 بذكاء على **~150-200 trajectory عالية الجودة**.
- باقي الـ 600 trajectory لازم نستنى تجديد CodeCraft أو نلاقي بديل.
- **Backup plan:** لو ما قدرناش نجمع 800، 200 trajectory عالية الجودة ممكن تكفي لـ 14B QLoRA مع data augmentation.

---

## 3. الاستراتيجية — 5 ركائز متكاملة

### الركيزة 1: Massive Distillation من Claude (الأهم)

**المشكلة:** النموذج اتدرب على 108 مثال بس من v3 prompts، وبيشتغل بـ v4. عدم تطابق قاتل.

**الحل:**
- جمع 200-800 trajectory مؤكدة من Claude على:
  - الـ 35 حالة في الـ benchmark (× 5-10 attempts لكل finding)
  - 20-30 حالة إضافية من npm packages معروفة الثغرات (Snyk/GHSA DB)
- حفظ **كل التفكير** مش بس الـ harness النهائي:
  - call chain analysis step-by-step
  - argument reasoning (ليه الـ input ده بالذات)
  - setup requirements (preconditions)
  - fuzz loop iterations

**الأداة:** Claude Code Cloud sessions (موازية 5-8 session)
**الميزانية:** $40-50 من الـ $54 المتاح
**المخرجات:** `training/data/distill-v5.jsonl` (200+ examples)

### الركيزة 2: Model Upgrade (7B → 14B)

**السبب:** 7B عنده سقف معماري. 14B بيلحق ~75-85% من teacher، بينما 7B بيلحق 50-60% فقط.

**التفاصيل التقنية:**
- النموذج: `unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit`
- Training: Kaggle 2x T4 (30GB VRAM فعّال)
- QLoRA (r=16, alpha=32) على attention + MLP
- Context: 2048 tokens
- Epochs: 3، batch size: 1، grad accumulation: 8
- وقت التدريب: ~10-14 ساعة/epoch

**Fallback:** لو 14B ماينفعش → 7B بـ 4096 context + distillation أكبر

**المخرجات:** `models/harness-adapter-14b-v5`

### الركيزة 3: Static Precomputation v2

**الحالي:** v4 بيحقن الـ call chain فقط.

**v5 بيضيف:**
- **Argument types** في كل خطوة في الـ chain (tree-sitter + type inference)
- **Preconditions** المطلوبة قبل الـ sink
- **Return type expectations** في كل خطوة
- **Branch coverage hints** (أي branches في الـ chain لازم تتاخد)

**الأثر المتوقع:** +10-15pp في reached (من 15% → 25-30%)

**المخرجات:** تعديل في `src/proofhound/core/analysis/call_chain.py`

### الركيزة 4: Rejection Sampling at Inference

**المبدأ:** 7B/14B بيفشل في المحاولة الواحدة؟ خليه يجرّب 5 بـ temperatures مختلفة.

**التفاصيل:**
- كل finding: 5 attempts بـ temps `[0.1, 0.3, 0.5, 0.7, 0.9]`
- Early exit: أول واحدة تأكّد → stop
- Fallback: لو مفيش confirm، ناخد أحسن reached
- التكلفة: GPU time فقط (محلي، مجاناً)

**الأثر المتوقع:** +15-25pp في confirmed

**المخرجات:** `src/proofhound/core/harness/sampling.py`

### الركيزة 5: Class-Aware Fuzzer Seeds

**المشكلة الحالية:** redos (57 finding) بـ 0 confirmed.

**الحل:** seed templates حسب نوع الثغرة:

```
data/seeds/
  redos_seeds.json          # catastrophic regex inputs: 'a'*1000 + '!', nested quantifiers
  path_traversal_seeds.json # ../../../etc/passwd, encoded, null bytes
  proto_pollution_seeds.json # {"__proto__": {...}}, {"constructor": {...}}
  cmd_injection_seeds.json  # ; ls, $(id), `whoami`, |cat, &&echo
```

**الاستخدام:** تحقن في Jazzer corpus قبل الـ fuzz run.

**الأثر المتوقع:**
- redos: من 0% → 40-60% من reached
- path-traversal: من 67% → 80%+
- cmd-injection: من 25% → 60%+

**المخرجات:** `data/seeds/*.json` + تعديل في harness runner

---

## 4. المراحل التنفيذية

### المرحلة 0: تحليل الفشل (يوم واحد) — بدأت

- [x] جمع نتائج الـ eval (108 finding)
- [ ] تصنيف كل failure: `env-blocked` / `reach-fail` / `confirm-fail` / `false-positive`
- [ ] تحديد Claude's expected confirmed set على نفس الـ 12 حالة
- [ ] تقرير `runs/compare-v4-full/failure_analysis.md`

### المرحلة 1: Distillation Farm (أسبوع — Oct 25 → Nov 1)

**استراتيجية الـ $54 Cloud credit:**

| النشاط | الـ sessions | التكلفة |
|---|---|---|
| POC: 1 finding بسيط | 1 | ~$0.25 |
| Easy findings (10 حالات، 30 findings) | 10 sessions | ~$5 |
| Medium findings (10 حالات، 40 findings) | 20 sessions | ~$15 |
| Hard findings (15 حالات، 50 findings) | 30 sessions | ~$25 |
| Buffer | — | ~$5 |
| **المجموع** | **~60 sessions** | **~$50** |

**المخرجات:**
- `scripts/distill_farm/orchestrator.py` (محلي، بيدير الـ pool)
- `scripts/distill_farm/worker_brief.md` (الـ brief لكل session)
- `training/data/distill-v5.jsonl` (120-200 confirmed trajectory)

**معيار النجاح:** 120+ confirmed trajectory قبل Nov 5

### المرحلة 2: Training 14B على Kaggle (3-4 أيام — Nov 1 → Nov 5)

- [ ] تجهيز الـ dataset في ChatML format
- [ ] تحديث notebook `training/train/kaggle/kaggle_train_14b.ipynb`
- [ ] Dry run على 10 examples للتأكد من إعدادات الـ VRAM
- [ ] Full training run (~30 ساعة إجمالاً، 2 Kaggle sessions)
- [ ] Export adapter لـ `models/harness-adapter-14b-v5`

**معيار النجاح:** eval loss ينزل بـ ≥40% عن الـ initial

### المرحلة 3: Inference Enhancements (أسبوع — Nov 5 → Nov 12)

- [ ] Static precomputation v2 (call_chain.py)
- [ ] Rejection sampling module (sampling.py)
- [ ] Class-aware seeds (data/seeds/*.json)
- [ ] تعديل compare.py لاستخدام الـ 3 features الجديدة
- [ ] اختبار على 2-3 حالات للتأكد من الـ integration

### المرحلة 4: Final Evaluation (3-5 أيام — Nov 12 → Nov 17)

- [ ] Full run للـ 14B v5 على 35 حالة
- [ ] Full run للـ Claude على نفس الـ 35 حالة (ناخد الـ reference set)
- [ ] حساب الـ metric الحقيقي: `|ours ∩ claude| / |claude|`
- [ ] تحليل كل finding فردياً (ablation بالركيزة)
- [ ] تقرير `reports/final_v5_comparison.md`

**معيار النجاح:** تطابق ≥85% من confirmed Claude set

### المرحلة 5: Buffer + تجهيز المناقشة (شهر — Nov 17 → Dec 25)

- [ ] تحسينات على أساس نتايج Phase 4
- [ ] Ablation study شامل (كل ركيزة ضافت كام pp)
- [ ] تقرير فني كامل (PDF)
- [ ] Side-by-side demo
- [ ] جدول Q&A متوقعة للمناقشة
- [ ] Dry run للمناقشة

---

## 5. التوقعات الواقعية

| المرحلة | Reached | Confirmed | نسبة من Claude |
|---|---|---|---|
| **الحالي (7B v4)** | 15% | 3.7% | ~10-15% |
| + 14B بس | 25-30% | 8-12% | 25-35% |
| + Distillation 200 | 35-45% | 15-20% | 45-55% |
| + Static Precompute v2 | 45-55% | 18-25% | 55-65% |
| + Rejection Sampling | 50-60% | 25-35% | 70-80% |
| **+ Class-aware Seeds (نهائي)** | **55-65%** | **35-45%** | **85-92%** ✅ |

**الهدف الواقعي:** 85-92% من Claude
**Stretch:** 95%
**Backup framing لو ما وصلناش 90%:** "نأكد X% من ثغرات كلود بـ 0 تكلفة متكررة ومحلياً 100%"

---

## 6. المخاطر وخطط الطوارئ

| الخطر | الاحتمال | التأثير | الخطة |
|---|---|---|---|
| 14B بيعمل OOM على Kaggle | متوسط | عالي | Fallback لـ 7B بـ 4096 context |
| Cloud credits تخلص قبل 150 trajectory | عالي | عالي | نستخدم Pro subscription limits + CodeCraft tier مرة واحدة |
| Distillation data جودتها ضعيفة | منخفض | عالي | Quality filter: نقبل بس اللي crash_confirmed=True |
| Static precompute كسرت الـ prompt | منخفض | متوسط | A/B test قبل الـ full run |
| 14B بيدي reach أعلى بس confirm أقل | متوسط | متوسط | class-aware seeds يعوّضوا |

---

## 7. المعايير الدفاعية للمناقشة

**لو وصلنا 90%+ (الأفضل):**
> "نموذج Qwen2.5-Coder-14B مُدرَّب على 200 trajectory مُقطَّرة من Claude Opus 5.5، بيأكد 92% من الثغرات اللي بيأكدها Claude على benchmark من 35 npm package، بتكلفة inference صفر و$Y training وقت واحد."

**لو وصلنا 75-90% (مقبول):**
> "تطابق 80% من قدرة Claude المغلق، بـ 1/100 التكلفة الدائمة، مع إمكانية تشغيل on-prem بالكامل."

**لو ما وصلناش 75% (سيناريو أسوأ):**
> على ثغرات path-traversal وcommand-injection تحديداً (اللي بتاع هدف البحث)، النموذج بيحقق 85% من قدرة Claude.

---

## 8. الخطوة الفورية التالية

1. **أعمل سكربت تحليل فشل** يقرا الـ attempts JSONL ويصنّف الـ failures.
2. **أجهّز POC لـ Cloud session distillation** على finding واحد معروف إنه بيتأكد.
3. **لو POC نجح**، أطلق الـ farm على 5-8 sessions بالتوازي.

---

**آخر تحديث:** 2026-10-25
**المسؤول:** mb82n3@gmail.com
