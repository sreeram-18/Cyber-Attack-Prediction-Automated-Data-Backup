import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

COLS = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
"root_shell","su_attempted","num_root","num_file_creations","num_shells",
"num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
"srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
"same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
"label","difficulty"]

train = pd.read_csv("KDDTrain+_20Percent.txt", names=COLS)
test = pd.read_csv("KDDTest+.txt", names=COLS)

train["target"] = (train["label"] != "normal").astype(int)
test["target"] = (test["label"] != "normal").astype(int)

X_train = train.drop(columns=["label","difficulty","target"])
y_train = train["target"]
X_test = test.drop(columns=["label","difficulty","target"])
y_test = test["target"]

categorical = ["protocol_type","service","flag"]
numeric = [c for c in X_train.columns if c not in categorical]

preprocessor = ColumnTransformer([
    ("categorical", OneHotEncoder(handle_unknown="ignore"), categorical),
    ("numeric", "passthrough", numeric)
])

model = RandomForestClassifier(
    n_estimators=100, random_state=42, n_jobs=-1, class_weight="balanced"
)

pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("random_forest", model)
])

pipeline.fit(X_train, y_train)
pred = pipeline.predict(X_test)

print("Accuracy:", accuracy_score(y_test, pred))
print("\nClassification Report:")
print(classification_report(y_test, pred, target_names=["Normal","Attack"], digits=4))
print("Confusion Matrix:")
print(confusion_matrix(y_test, pred))

joblib.dump(pipeline, "nsl_kdd_random_forest_78_baseline.pkl")
print("\nModel saved as nsl_kdd_random_forest_78_baseline.pkl")
