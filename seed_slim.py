"""
Slim seeder for minimal installs (no scikit-learn / shap / pandas).

Seeds roles, demo users, patient records, synthetic audit history and
behavioral baselines. ML model training is skipped; the app detects the
missing models and automatically falls back to rule-based risk scoring
plus rule-weight explanations.

Run once after first install:
    python seed_slim.py
"""

import hashlib
import random
from datetime import datetime, timedelta

from app import create_app
from extensions import db, bcrypt
from models import Role, User, PatientRecord, AuditLog

random.seed(42)

ROLE_NAMES = ["admin", "doctor", "nurse", "staff"]

DEMO_USERS = [
    ("admin1", "Admin@1234", "admin"),
    ("dr_rahim", "Doctor@1234", "doctor"),
    ("nurse_akter", "Nurse@1234", "nurse"),
    ("staff_hasan", "Staff@1234", "staff"),
]

PATIENT_RECORDS = [
    ("Abdul Karim", "Type 2 Diabetes", "HbA1c 8.2%, on Metformin 500mg BD, follow-up in 3 months."),
    ("Fatema Begum", "Hypertension", "BP 150/95, prescribed Amlodipine 5mg, advise low-sodium diet."),
    ("Mohammad Ali", "Post-op Appendectomy", "Day 3 post-surgery, wound healing well, discharge planned."),
    ("Rina Akter", "Asthma", "Frequent nocturnal symptoms, stepped up to ICS/LABA combination."),
    ("Kamal Hossain", "Chronic Kidney Disease Stage 3", "eGFR 45, referred to nephrology, monitor electrolytes."),
    ("Salma Khatun", "Pregnancy - 3rd Trimester", "32 weeks, routine antenatal checkup, all parameters normal."),
    ("Jashim Uddin", "Coronary Artery Disease", "Post-angioplasty, on dual antiplatelet therapy, cardiac rehab advised."),
    ("Nasrin Sultana", "Major Depressive Disorder", "On SSRIs, biweekly counseling, mood improving."),
    ("Habibur Rahman", "Fractured Femur", "ORIF performed, physiotherapy started, non-weight-bearing x 6 weeks."),
    ("Shirin Aktar", "Thyroid Disorder", "TSH elevated, Levothyroxine dose adjusted, recheck in 6 weeks."),
    ("Anwar Hossain", "Acute Myocardial Infarction", "STEMI managed with primary PCI, on dual antiplatelet + statin, cardiology follow-up in 2 weeks."),
    ("Marium Akter", "Migraine", "Recurrent unilateral headaches, started on Propranolol prophylaxis, headache diary advised."),
    ("Delwar Hossain", "Chronic Obstructive Pulmonary Disease", "FEV1 58% predicted, on Tiotropium + salbutamol PRN, smoking cessation counseling given."),
    ("Ayesha Siddiqua", "Gestational Diabetes", "OGTT positive at 26 weeks, started on dietary modification and glucose monitoring."),
    ("Rafiqul Islam", "Peptic Ulcer Disease", "H. pylori positive, started on triple therapy, advised avoid NSAIDs."),
    ("Taslima Begum", "Rheumatoid Arthritis", "DAS28 score elevated, on Methotrexate weekly, folic acid supplementation."),
    ("Shahidul Islam", "Stroke - Ischemic", "Left MCA infarct, on Aspirin + Atorvastatin, physiotherapy and speech therapy started."),
    ("Nazma Khatun", "Urinary Tract Infection", "E. coli on culture, started on Nitrofurantoin, advised increased fluid intake."),
    ("Golam Mostafa", "Benign Prostatic Hyperplasia", "IPSS score moderate, started on Tamsulosin, urology follow-up in 6 weeks."),
    ("Ruma Aktar", "Iron Deficiency Anemia", "Hb 8.5 g/dL, started on oral iron, dietary counseling given, recheck CBC in 4 weeks."),
    ("Mizanur Rahman", "Acute Pancreatitis", "Mild gallstone pancreatitis, NPO then gradual diet, surgery consult for cholecystectomy."),
    ("Poly Rani Das", "Epilepsy", "Generalized tonic-clonic seizures, on Sodium Valproate, EEG follow-up scheduled."),
    ("Aminul Islam", "Chronic Liver Disease", "Child-Pugh B cirrhosis, on diuretics, ultrasound surveillance every 6 months."),
    ("Sultana Razia", "Preeclampsia", "BP 160/100 at 34 weeks, admitted for monitoring, on Labetalol and antenatal steroids."),
    ("Faruk Ahmed", "Diabetic Foot Ulcer", "Grade 2 ulcer left foot, on wound dressing and IV antibiotics, vascular surgery referral."),
    ("Roksana Begum", "Bronchial Pneumonia", "Right lower lobe consolidation, started on IV Ceftriaxone, O2 saturation monitored."),
    ("Shamsul Alam", "Gout", "Acute flare right great toe, uric acid 9.2 mg/dL, started on Colchicine and Allopurinol."),
    ("Nusrat Jahan", "Polycystic Ovary Syndrome", "Irregular cycles and insulin resistance, started on Metformin, lifestyle counseling given."),
    ("Ekramul Haque", "Chronic Hepatitis B", "Viral load elevated, started on Tenofovir, liver function monitored quarterly."),
    ("Farida Yasmin", "Osteoporosis", "T-score -3.1 on DEXA, started on Alendronate weekly, calcium and vitamin D advised."),
    ("Kabir Hossain", "Testicular Trauma", "Post scrotal injury, ultrasound normal, conservative management with analgesia."),
    ("Hasina Akter", "Acute Gastroenteritis", "Dehydration moderate, on IV fluids and ORS, stool culture pending."),
    ("Mostafizur Rahman", "Chronic Sinusitis", "Recurrent purulent discharge, started on Amoxicillin-clavulanate, ENT referral."),
    ("Lucky Akter", "Cervical Spondylosis", "Neck pain with radiculopathy, on physiotherapy and NSAIDs, MRI advised if no improvement."),
    ("Iqbal Hasan", "Deep Vein Thrombosis", "Left leg swelling, Doppler confirmed DVT, started on anticoagulation therapy."),
    ("Champa Rani", "Hyperthyroidism", "Graves disease suspected, on Carbimazole, thyroid function recheck in 4 weeks."),
    ("Nurul Amin", "Chronic Kidney Disease Stage 4", "eGFR 22, dietary protein restriction advised, dialysis planning discussed."),
    ("Selina Parvin", "Endometriosis", "Chronic pelvic pain, on hormonal therapy, gynecology follow-up in 8 weeks."),
    ("Zakir Hossain", "Acute Cholecystitis", "Murphy's sign positive, on IV antibiotics, laparoscopic cholecystectomy planned."),
    ("Rownak Jahan", "Postpartum Hemorrhage", "Managed with uterotonics and IV fluids, hemoglobin stable post-transfusion."),
    ("Aktar Hossain", "Peripheral Neuropathy", "Diabetic neuropathy, on Pregabalin, glycemic control optimization advised."),
    ("Monira Khatun", "Chronic Migraine with Aura", "Visual aura preceding headache, MRI brain normal, on Topiramate prophylaxis."),
    ("Shafiqul Islam", "Inguinal Hernia", "Reducible right inguinal hernia, elective herniorrhaphy scheduled."),
    ("Yasmin Sultana", "Systemic Lupus Erythematosus", "ANA positive, on Hydroxychloroquine, renal function monitored."),
    ("Babul Mia", "Acute Kidney Injury", "Post-dehydration AKI, creatinine trending down with IV fluids, nephrology consult."),
    ("Rehana Parvin", "Vitiligo", "Progressive depigmentation, started on topical corticosteroids, dermatology follow-up."),
    ("Alamgir Hossain", "Chronic Low Back Pain", "MRI shows L4-L5 disc bulge, on physiotherapy and analgesics, surgery not indicated yet."),
    ("Jesmin Akter", "Hypothyroidism in Pregnancy", "TSH elevated at 12 weeks, Levothyroxine dose increased, recheck in 4 weeks."),
    ("Nazrul Islam", "Acute Bronchitis", "Productive cough 5 days, supportive treatment with bronchodilator, no antibiotics indicated."),
    ("Tahmina Akhter", "Ovarian Cyst", "6cm simple cyst on ultrasound, conservative management, follow-up scan in 8 weeks."),
    ("Moinul Islam", "Chronic Pancreatitis", "Recurrent epigastric pain, enzyme replacement started, advised alcohol cessation."),
    ("Sabina Yasmin", "Meniere's Disease", "Vertigo with tinnitus, started on Betahistine, low-salt diet advised."),
    ("Harun Or Rashid", "Prostate Cancer - Localized", "PSA 8.4, biopsy confirmed Gleason 6, urology-oncology MDT discussion planned."),
    ("Rupa Akter", "Postoperative Wound Infection", "Cesarean site infection, on IV antibiotics, daily dressing change."),
    ("Delower Hossain", "Chronic Heart Failure", "EF 35%, on ACE inhibitor, beta-blocker and diuretic, fluid restriction advised."),
    ("Nasima Begum", "Cataract - Bilateral", "Visual acuity reduced, phacoemulsification planned right eye first, ophthalmology follow-up."),
]


def seed_roles_and_users():
    for name in ROLE_NAMES:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name))
    db.session.commit()

    for username, password, role_name in DEMO_USERS:
        if User.query.filter_by(username=username).first():
            continue
        role = Role.query.filter_by(name=role_name).first()
        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        db.session.add(User(username=username, password_hash=pw_hash, role_id=role.id))
    db.session.commit()
    print(f"Seeded roles {ROLE_NAMES} and {len(DEMO_USERS)} demo users.")


def seed_patient_records():
    if PatientRecord.query.count() > 0:
        print("Patient records already present, skipping.")
        return
    for name, diagnosis, notes in PATIENT_RECORDS:
        db.session.add(PatientRecord(patient_name=name, diagnosis=diagnosis, sensitive_notes=notes))
    db.session.commit()
    print(f"Seeded {len(PATIENT_RECORDS)} patient records.")


def seed_synthetic_audit_history():
    clinical_users = User.query.join(Role).filter(Role.name.in_(["doctor", "nurse"])).all()
    if AuditLog.query.count() > 5:
        print("Audit history already present, skipping synthetic history generation.")
        return

    prev_hash = "0" * 64
    entries = []
    now = datetime.utcnow()
    for user in clinical_users:
        for day in range(30, 0, -1):
            day_dt = now - timedelta(days=day)
            if day_dt.weekday() >= 5:
                continue
            session_start_hour = random.choice([8, 9, 9, 10, 14])
            n_actions = random.randint(3, 9)
            t = day_dt.replace(hour=session_start_hour, minute=random.randint(0, 59), second=0, microsecond=0)
            for _ in range(n_actions):
                t = t + timedelta(seconds=random.randint(30, 240))
                entries.append((user, "VIEW_PATIENT_RECORD", t))

    for user, action, ts in entries:
        payload = f"{prev_hash}|{user.id}|{action}|synthetic|127.0.0.1|{ts.isoformat()}"
        curr_hash = hashlib.sha256(payload.encode()).hexdigest()
        db.session.add(AuditLog(
            user_id=user.id, username_snapshot=user.username, action=action,
            resource="synthetic_seed_data", ip_address="127.0.0.1", timestamp=ts,
            prev_hash=prev_hash, curr_hash=curr_hash,
        ))
        prev_hash = curr_hash
    db.session.commit()
    print(f"Seeded {len(entries)} synthetic historical audit events for behavioral baselines.")

    from behavior_biometrics import build_or_refresh_profile
    for user in clinical_users:
        build_or_refresh_profile(user.id)
    print("Built initial BehaviorProfile baselines.")


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
        seed_roles_and_users()
        seed_patient_records()
        seed_synthetic_audit_history()
        print("NOTE: ML models not trained (slim install). App runs in rule-based mode.")
        print("\nSlim seeding complete. Demo login credentials:")
        for username, password, role in DEMO_USERS:
            print(f"  {role:8s} -> username: {username:15s} password: {password}")
