"""
Evaluation Metrics for Insider Threat Detection
Calculates Precision, Recall, F1 Score, and Confusion Matrix
Uses anomaly_marker as ground truth
"""

import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, classification_report
import json
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(__file__))

from detector import load_and_merge_data, feature_engineering, train_and_predict


def evaluate_detector(logs_path, profiles_path, threshold=70):
    """
    Evaluate the detector against ground truth labels.
    
    Args:
        logs_path: Path to CSV logs
        profiles_path: Path to CSV profiles
        threshold: Risk score threshold for positive prediction
    
    Returns:
        Dictionary with evaluation metrics
    """
    
    # Load and process data
    df = load_and_merge_data(logs_path, profiles_path)
    df = feature_engineering(df)
    df = train_and_predict(df)
    
    # Ground truth: 1 if anomaly_marker is not null, 0 otherwise
    y_true = (df['anomaly_marker'].notna()).astype(int)
    
    # Predictions: 1 if risk_score >= threshold, 0 otherwise
    y_pred = (df['risk_score'] >= threshold).astype(int)
    
    # Calculate metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    # Calculate additional metrics
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    # Prepare results
    results = {
        'threshold': threshold,
        'total_samples': len(df),
        'ground_truth_positives': int(y_true.sum()),
        'predicted_positives': int(y_pred.sum()),
        'metrics': {
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'specificity': round(specificity, 4),
            'false_positive_rate': round(fpr, 4),
            'false_negative_rate': round(fnr, 4)
        },
        'confusion_matrix': {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        },
        'classification_report': classification_report(
            y_true, y_pred,
            target_names=['Normal', 'Threat'],
            output_dict=True
        )
    }
    
    return results


def print_evaluation_report(results):
    """Pretty print the evaluation results."""
    print("\n" + "="*60)
    print("🔍 INSIDER THREAT DETECTOR - EVALUATION REPORT")
    print("="*60)
    
    print(f"\n📊 Dataset Statistics:")
    print(f"   Total Samples: {results['total_samples']}")
    print(f"   Ground Truth Positives (True Threats): {results['ground_truth_positives']}")
    print(f"   Predicted Positives: {results['predicted_positives']}")
    print(f"   Detection Threshold: {results['threshold']}")
    
    print(f"\n📈 Performance Metrics:")
    metrics = results['metrics']
    print(f"   Precision: {metrics['precision']:.4f}  (How many detected threats are real)")
    print(f"   Recall:    {metrics['recall']:.4f}  (How many real threats are detected)")
    print(f"   F1 Score:  {metrics['f1_score']:.4f}  (Harmonic mean of precision and recall)")
    print(f"   Specificity: {metrics['specificity']:.4f}  (True negative rate)")
    print(f"   FPR:       {metrics['false_positive_rate']:.4f}  (False alarm rate)")
    print(f"   FNR:       {metrics['false_negative_rate']:.4f}  (Miss rate)")
    
    print(f"\n🎯 Confusion Matrix:")
    cm = results['confusion_matrix']
    print(f"   TP (True Positives):   {cm['true_positives']:4d}  │  FN (False Negatives): {cm['false_negatives']:4d}")
    print(f"   FP (False Positives):  {cm['false_positives']:4d}  │  TN (True Negatives):  {cm['true_negatives']:4d}")
    
    print(f"\n📋 Classification Report:")
    print("\n   Class      | Precision | Recall | F1-Score | Support")
    print("   " + "-" * 54)
    report = results['classification_report']
    for label, metrics_dict in report.items():
        if label != 'accuracy' and isinstance(metrics_dict, dict):
            print(f"   {label:10s} | {metrics_dict['precision']:9.4f} | {metrics_dict['recall']:6.4f} | {metrics_dict['f1-score']:8.4f} | {int(metrics_dict['support']):6d}")
    
    print("\n" + "="*60 + "\n")


def save_evaluation_report(results, output_path='../outputs/evaluation_report.json'):
    """Save evaluation results to JSON."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"✅ Evaluation report saved to: {output_path}")


if __name__ == "__main__":
    logs_path = "../data/data_access_logs.csv"
    profiles_path = "../data/user_profiles.csv"
    
    # Test different thresholds
    thresholds = [50, 60, 70, 80, 90]
    
    print("\n🧪 Testing Multiple Thresholds:")
    all_results = {}
    
    for threshold in thresholds:
        print(f"\n   Testing threshold: {threshold}...")
        results = evaluate_detector(logs_path, profiles_path, threshold=threshold)
        all_results[threshold] = results
        print(f"   ✅ F1 Score: {results['metrics']['f1_score']:.4f}")
    
    # Print detailed report for threshold 70
    print("\n\n🎯 Detailed Report (Threshold=70):")
    print_evaluation_report(all_results[70])
    
    # Save all results
    save_evaluation_report(all_results, '../outputs/evaluation_results.json')
    
    print("\n✨ Evaluation Complete!")
