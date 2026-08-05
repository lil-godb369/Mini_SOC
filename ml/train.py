"""Huấn luyện và đánh giá mô hình phát hiện xâm nhập trên CIC-IDS2017.

    python train.py --data-dir data/raw --out artifacts

Ba mô hình được huấn luyện và so sánh:

* **RandomForest** — đường cơ sở. Mạnh trên dữ liệu dạng bảng, chịu được đặc
  trưng lệch thang đo mà không cần chuẩn hoá, và cho ra độ quan trọng đặc trưng
  giải thích được.
* **XGBoost** — boosting thường nhỉnh hơn rừng ngẫu nhiên vài phần trăm trên dữ
  liệu bảng, đổi lại khó chỉnh siêu tham số hơn.
* **IsolationForest** — đường cơ sở KHÔNG GIÁM SÁT. Nó chỉ học từ lưu lượng
  lành tính. Có nó trong báo cáo để trả lời một câu hỏi thực tế: một SMB không
  có dữ liệu tấn công đã gán nhãn thì làm được đến đâu?

Không dùng mạng nơ-ron sâu: máy không có GPU, và trên dữ liệu DẠNG BẢNG thì các
mô hình cây tập hợp vẫn thắng deep learning một cách nhất quán trong tài liệu
nghiên cứu. Đây là lựa chọn có căn cứ, không phải né việc.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from preprocess import (
    BENIGN_LABEL,
    clean,
    load_raw,
    split_by_day,
    summarize_labels,
    to_binary,
)

logger = logging.getLogger(__name__)

RANDOM_STATE = 42


# ---------------------------------------------------------------------------
# Nạp dữ liệu
# ---------------------------------------------------------------------------
def load_dataset(
    data_dir: Optional[Path], processed_dir: Optional[Path], keep_port: bool
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Ưu tiên dữ liệu đã tiền xử lý (nhanh hơn nhiều), nếu không thì đọc CSV thô."""
    if processed_dir and (processed_dir / "features.parquet").exists():
        logger.info("Nạp dữ liệu đã tiền xử lý từ %s", processed_dir)
        X = pd.read_parquet(processed_dir / "features.parquet")
        meta = pd.read_parquet(processed_dir / "labels.parquet")
        return X, meta["label"], meta["day"]

    logger.info("Nạp và làm sạch CSV thô từ %s", data_dir)
    return clean(load_raw(data_dir), keep_destination_port=keep_port)


# ---------------------------------------------------------------------------
# Đánh giá
# ---------------------------------------------------------------------------
def evaluate(y_true, y_pred, y_score=None, labels: Optional[List] = None) -> Dict:
    """Bộ số liệu đầy đủ cho báo cáo.

    Báo cáo CẢ macro-F1 lẫn weighted-F1 là có chủ ý. Trong CIC-IDS2017, hơn 80%
    số dòng là lành tính, nên weighted-F1 (và accuracy) bị lớp đa số chi phối và
    trông đẹp một cách sai lệch. Macro-F1 đối xử mọi lớp như nhau, nên nó phơi
    bày việc mô hình bỏ sót các lớp hiếm — mà lớp hiếm (Heartbleed chỉ có 11 mẫu)
    lại chính là thứ nguy hiểm nhất ngoài đời.
    """
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }

    # Với bài toán nhị phân, precision/recall của LỚP TẤN CÔNG mới là con số
    # người vận hành SOC quan tâm: bỏ sót bao nhiêu cuộc tấn công, và báo nhầm
    # bao nhiêu lần khiến người trực mất niềm tin.
    unique = sorted(set(np.unique(y_true)) | set(np.unique(y_pred)))
    if len(unique) == 2:
        metrics["precision_attack"] = float(
            precision_score(y_true, y_pred, pos_label=1, zero_division=0)
        )
        metrics["recall_attack"] = float(
            recall_score(y_true, y_pred, pos_label=1, zero_division=0)
        )
        metrics["f1_attack"] = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
        if y_score is not None:
            try:
                metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
            except ValueError:
                metrics["roc_auc"] = None

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    metrics["confusion_matrix"] = cm.tolist()
    metrics["confusion_matrix_labels"] = [str(l) for l in (labels if labels is not None else unique)]
    metrics["per_class"] = classification_report(
        y_true, y_pred, output_dict=True, zero_division=0
    )

    if len(unique) == 2 and cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        metrics["true_negatives"] = int(tn)
        metrics["false_positives"] = int(fp)
        metrics["false_negatives"] = int(fn)
        metrics["true_positives"] = int(tp)
        # Tỉ lệ báo động giả: chỉ số quyết định hệ thống có dùng được ở SMB không.
        metrics["false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
        metrics["false_negative_rate"] = float(fn / (fn + tp)) if (fn + tp) else 0.0

    return metrics


def print_report(name: str, metrics: Dict) -> None:
    print(f"\n{'=' * 68}\n  {name}\n{'=' * 68}")
    print(f"  Accuracy          : {metrics['accuracy']:.4f}")
    print(f"  F1 (macro)        : {metrics['f1_macro']:.4f}   <- con so trung thuc nhat")
    print(f"  F1 (weighted)     : {metrics['f1_weighted']:.4f}")
    if "recall_attack" in metrics:
        print(f"  Precision (tan cong): {metrics['precision_attack']:.4f}")
        print(f"  Recall    (tan cong): {metrics['recall_attack']:.4f}   <- bo sot bao nhieu")
        print(f"  F1        (tan cong): {metrics['f1_attack']:.4f}")
    if metrics.get("roc_auc") is not None:
        print(f"  ROC-AUC           : {metrics['roc_auc']:.4f}")
    if "false_positive_rate" in metrics:
        print(f"  Ty le bao dong gia : {metrics['false_positive_rate']:.4%}")
        print(f"  Ty le bo sot       : {metrics['false_negative_rate']:.4%}")
    print("\n  Ma tran nham lan (hang = that, cot = du doan):")
    for label, row in zip(metrics["confusion_matrix_labels"], metrics["confusion_matrix"]):
        print(f"    {label:>10} | " + " ".join(f"{v:>9,}" for v in row))


# ---------------------------------------------------------------------------
# Huấn luyện
# ---------------------------------------------------------------------------
def train_random_forest(X_train, y_train, n_jobs: int = -1):
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_leaf=2,
        # Dữ liệu lệch nặng về lớp lành tính; không cân bằng lại thì mô hình học
        # được mẹo "đoán lành tính là xong" và vẫn đạt accuracy ~80%.
        class_weight="balanced_subsample",
        n_jobs=n_jobs,
        random_state=RANDOM_STATE,
    )
    model.fit(X_train, y_train)
    return model


def train_xgboost(X_train, y_train, n_jobs: int = -1):
    try:
        from xgboost import XGBClassifier
    except ImportError:
        logger.warning("Chưa cài xgboost — bỏ qua mô hình này")
        return None

    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    scale = (n_neg / n_pos) if n_pos else 1.0

    model = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale,   # cách xử lý mất cân bằng của XGBoost
        tree_method="hist",       # nhanh hơn nhiều trên CPU
        n_jobs=n_jobs,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    return model


def train_isolation_forest(X_train, y_train):
    """Đường cơ sở không giám sát: CHỈ học từ lưu lượng lành tính."""
    from sklearn.ensemble import IsolationForest

    X_benign = X_train[y_train == 0]
    if len(X_benign) == 0:
        return None

    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,   # giả định ~1% lưu lượng nền là bất thường
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    model.fit(X_benign)
    return model


def feature_importance(model, feature_names: List[str], top: int = 20) -> List[Dict]:
    importances = getattr(model, "feature_importances_", None)
    if importances is None:
        return []
    order = np.argsort(importances)[::-1][:top]
    return [
        {"feature": feature_names[i], "importance": float(importances[i])} for i in order
    ]


# ---------------------------------------------------------------------------
# Lưu artifact
# ---------------------------------------------------------------------------
def save_bundle(out_dir: Path, name: str, model, feature_names: List[str], metadata: Dict) -> Path:
    """Lưu mô hình kèm THỨ TỰ ĐẶC TRƯNG.

    Lưu kèm danh sách đặc trưng là bắt buộc, không phải cho đẹp: lúc suy luận,
    các đặc trưng phải được xếp đúng thứ tự lúc huấn luyện. Nếu không, mô hình
    vẫn chạy và vẫn trả về số — nhưng là số vô nghĩa. Đây là kiểu lỗi im lặng
    nguy hiểm nhất khi triển khai học máy.
    """
    import joblib

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.joblib"
    joblib.dump(
        {"model": model, "feature_names": list(feature_names), "metadata": metadata},
        path,
        compress=3,
    )
    logger.info("Đã lưu %s (%.1f MB)", path, path.stat().st_size / 1e6)
    return path


def plot_confusion_matrix(metrics: Dict, title: str, path: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("Chưa cài matplotlib — bỏ qua vẽ ma trận nhầm lẫn")
        return

    cm = np.array(metrics["confusion_matrix"])
    labels = metrics["confusion_matrix_labels"]

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Du doan")
    ax.set_ylabel("Thuc te")
    ax.set_title(title)

    threshold = cm.max() / 2 if cm.max() else 0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > threshold else "black", fontsize=9)

    fig.colorbar(im)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Đã lưu biểu đồ %s", path)


# ---------------------------------------------------------------------------
# Điều phối
# ---------------------------------------------------------------------------
def run(args) -> Dict:
    X, labels, days = load_dataset(args.data_dir, args.processed_dir, args.keep_destination_port)

    print("\n=== Phan bo nhan ===")
    print(summarize_labels(labels, days).to_string())

    y = to_binary(labels) if args.task == "binary" else labels

    if args.split == "day":
        X_train, X_test, y_train, y_test = split_by_day(X, y, days)
        split_note = (
            "Chia theo ngay: huan luyen Thu2-Thu4, kiem thu Thu5-Thu6. "
            "Cac kieu tan cong o tap kiem thu KHONG xuat hien trong tap huan luyen."
        )
    else:
        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=RANDOM_STATE, stratify=y
        )
        split_note = "Chia ngau nhien phan tang 70/30 (co nguy co ro ri giua cac luong cung phien)."

    print(f"\n{split_note}")
    print(f"Tap huan luyen: {len(X_train):,} dong | Tap kiem thu: {len(X_test):,} dong")

    feature_names = list(X_train.columns)
    results: Dict[str, Dict] = {}
    out_dir = Path(args.out)

    trainers = [
        ("random_forest", train_random_forest),
        ("xgboost", train_xgboost),
    ]

    for name, trainer in trainers:
        logger.info("Đang huấn luyện %s...", name)
        started = time.time()
        model = trainer(X_train.values, y_train.values)
        if model is None:
            continue
        elapsed = time.time() - started

        y_pred = model.predict(X_test.values)
        y_score = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_test.values)
            if proba.shape[1] == 2:
                y_score = proba[:, 1]

        metrics = evaluate(y_test.values, y_pred, y_score)
        metrics["training_seconds"] = round(elapsed, 1)
        metrics["top_features"] = feature_importance(model, feature_names)
        results[name] = metrics

        print_report(f"{name.upper()}  ({args.task}, chia theo {args.split})", metrics)
        if metrics["top_features"]:
            print("\n  10 dac trung quan trong nhat:")
            for row in metrics["top_features"][:10]:
                print(f"    {row['importance']:.4f}  {row['feature']}")

        save_bundle(out_dir, name, model, feature_names, {
            "task": args.task,
            "split": args.split,
            "split_note": split_note,
            "n_train": len(X_train),
            "n_test": len(X_test),
            "metrics": {k: v for k, v in metrics.items()
                        if k not in ("per_class", "confusion_matrix", "top_features")},
        })
        plot_confusion_matrix(metrics, f"{name} ({args.task})",
                              out_dir / f"confusion_matrix_{name}.png")

    # --- Đường cơ sở không giám sát ---
    if args.task == "binary" and not args.skip_unsupervised:
        logger.info("Đang huấn luyện isolation_forest (chỉ trên lưu lượng lành tính)...")
        iso = train_isolation_forest(X_train.values, y_train.values)
        if iso is not None:
            # IsolationForest tra ve -1 cho bat thuong, +1 cho binh thuong.
            y_pred = np.where(iso.predict(X_test.values) == -1, 1, 0)
            metrics = evaluate(y_test.values, y_pred)
            results["isolation_forest"] = metrics
            print_report("ISOLATION FOREST (khong giam sat, chi hoc tu luu luong lanh)", metrics)
            save_bundle(out_dir, "isolation_forest", iso, feature_names,
                        {"task": "binary", "split": args.split, "unsupervised": True})

    # --- Lưu toàn bộ số liệu để đưa thẳng vào báo cáo ---
    out_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = out_dir / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as fh:
        json.dump(
            {"task": args.task, "split": args.split, "split_note": split_note,
             "n_train": len(X_train), "n_test": len(X_test), "models": results},
            fh, indent=2, ensure_ascii=False,
        )
    print(f"\nDa ghi toan bo so lieu vao {metrics_path}")

    if results:
        best = max(results.items(), key=lambda kv: kv[1]["f1_macro"])
        print(f"\nMo hinh tot nhat theo macro-F1: {best[0]} ({best[1]['f1_macro']:.4f})")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Huấn luyện mô hình IDS trên CIC-IDS2017")
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--processed-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--out", type=Path, default=Path("artifacts"))
    parser.add_argument("--task", choices=["binary", "multiclass"], default="binary",
                        help="binary = lành tính/tấn công; multiclass = từng kiểu tấn công")
    parser.add_argument("--split", choices=["day", "stratified"], default="day",
                        help="day = chia theo ngày (chống rò rỉ, KHUYẾN NGHỊ)")
    parser.add_argument("--keep-destination-port", action="store_true")
    parser.add_argument("--skip-unsupervised", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")

    if args.task == "multiclass" and args.split == "day":
        print(
            "CANH BAO: multiclass + chia theo ngay se that bai co he thong, vi cac kieu "
            "tan cong cua Thu5-Thu6 khong he xuat hien trong tap huan luyen Thu2-Thu4.\n"
            "         Dung --split stratified cho bai toan multiclass.\n"
        )

    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
