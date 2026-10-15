import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Lecture du dataset ...")
df = pd.read_csv("dataset_v2.csv")
print(f"Dataset : {len(df)} connexions")
print(df["label"].value_counts())

X = df[["nb_packets", "total_bytes", "dport", "duration", "avg_size", "direction"]]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)
print(f"\nEntrainement : {len(X_train)} | Test : {len(X_test)}")

print("\nEntrainement du modele ...")
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\n=== RESULTATS ===")
print(classification_report(y_test, y_pred))
print("Matrice de confusion :")
print(confusion_matrix(y_test, y_pred))

print("\n=== Importance des features ===")
for feature, importance in sorted(zip(X.columns, model.feature_importances_), key=lambda x: -x[1]):
    print(f"{feature}: {importance:.3f}")

joblib.dump(model, "model_v2.pkl")
print("\nModele sauvegarde : model_v2.pkl")
