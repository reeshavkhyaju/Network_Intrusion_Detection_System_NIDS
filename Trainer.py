#!/usr/bin/python3
"""
Network Intrusion Detection System - Model Trainer
Trains a Logistic Regression model for binary classification (BENIGN vs Attack)
on collected network traffic data
"""

import pandas as pd
import numpy as np
import joblib
import os
import sys
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
import matplotlib.pyplot as plt
import seaborn as sns

class IDSTrainer:
    def __init__(self, data_file='collected_data.csv'):
        """
        Initialize the IDS Trainer
        
        Args:
            data_file: Path to the collected training data CSV
        """
        self.data_file = data_file
        self.df = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = None
        self.label_encoder = None
        self.model = None
        self.model_name = None
        
        print("\n" + "="*70)
        print("🎓 NETWORK IDS - BINARY CLASSIFIER (BENIGN vs Attack)")
        print("="*70)
    
    def load_data(self):
        """Load and validate the training data"""
        print("\n📂 LOADING DATA")
        print("-"*70)
        
        if not os.path.exists(self.data_file):
            print(f"❌ Error: Data file '{self.data_file}' not found!")
            print(f"   Please collect data using Data_Collector.py first.")
            return False
        
        try:
            self.df = pd.read_csv(self.data_file)
            print(f"✅ Loaded data from: {self.data_file}")
            print(f"   Total samples: {len(self.df):,}")
            print(f"   Total features: {len(self.df.columns)}")
            
            if 'Label' not in self.df.columns:
                print("❌ Error: 'Label' column not found in data!")
                return False
            
            print(f"\n📊 Label Distribution:")
            label_counts = self.df['Label'].value_counts()
            for label, count in label_counts.items():
                percentage = (count / len(self.df)) * 100
                print(f"   {label:<20}: {count:>7,} ({percentage:>5.2f}%)")
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return False
    
    def preprocess_data(self):
        """Preprocess and clean the data"""
        print("\n🔧 PREPROCESSING DATA")
        print("-"*70)
        
        try:
            # Check for missing values
            missing = self.df.isnull().sum().sum()
            if missing > 0:
                print(f"⚠️  Found {missing} missing values, filling with 0...")
                self.df.fillna(0, inplace=True)
            else:
                print("✅ No missing values found")
            
            # Remap labels: merge all non-BENIGN labels into 'Attack'
            self.df['Label'] = self.df['Label'].apply(
                lambda x: 'BENIGN' if x == 'BENIGN' else 'Attack'
            )
            print("✅ Labels remapped to binary: BENIGN vs Attack")
            label_counts = self.df['Label'].value_counts()
            for label, count in label_counts.items():
                percentage = (count / len(self.df)) * 100
                print(f"   {label:<20}: {count:>7,} ({percentage:>5.2f}%)")

            # Check for infinite values
            numeric_cols = self.df.select_dtypes(include=[np.number]).columns
            inf_mask = np.isinf(self.df[numeric_cols]).any(axis=1)
            inf_count = inf_mask.sum()
            
            if inf_count > 0:
                print(f"⚠️  Found {inf_count} rows with infinite values, replacing...")
                self.df[numeric_cols] = self.df[numeric_cols].replace([np.inf, -np.inf], 0)
            else:
                print("✅ No infinite values found")
            
            # Separate features and labels
            X = self.df.drop('Label', axis=1)
            y = self.df['Label']
            
            # Remove any non-numeric columns except Label
            non_numeric = X.select_dtypes(exclude=[np.number]).columns
            if len(non_numeric) > 0:
                print(f"⚠️  Removing non-numeric columns: {list(non_numeric)}")
                X = X.select_dtypes(include=[np.number])
            
            print(f"✅ Final feature count: {X.shape[1]}")
            print(f"✅ Total samples: {X.shape[0]:,}")
            
            # Encode labels
            self.label_encoder = LabelEncoder()
            y_encoded = self.label_encoder.fit_transform(y)
            
            print(f"\n📋 Encoded Labels:")
            for i, label in enumerate(self.label_encoder.classes_):
                print(f"   {label:<20} -> {i}")
            
            # Split data
            print(f"\n✂️  Splitting data (80% train, 20% test)...")
            self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
            
            print(f"   Training samples:   {len(self.X_train):,}")
            print(f"   Testing samples:    {len(self.X_test):,}")
            
            # Scale features
            print(f"\n⚖️  Scaling features...")
            self.scaler = StandardScaler()
            self.X_train = self.scaler.fit_transform(self.X_train)
            self.X_test = self.scaler.transform(self.X_test)
            
            print("✅ Data preprocessing completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error during preprocessing: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def train_model(self, algorithm='logistic', optimize=False):
        """
        Train the model using Logistic Regression for binary classification
        
        Args:
            algorithm: 'logistic' (default and only supported)
            optimize: Not used (kept for interface compatibility)
        """
        print("\n🎯 TRAINING MODEL")
        print("-"*70)
        
        self.model_name = 'logistic'
        
        try:
            print("📚 Algorithm: Logistic Regression (Binary: BENIGN vs Attack)")
            self.model = LogisticRegression(
                max_iter=1000,
                random_state=42,
                n_jobs=-1,
                solver='lbfgs'
            )
            
            print(f"\n⏳ Training in progress...")
            start_time = datetime.now()
            
            self.model.fit(self.X_train, self.y_train)
            
            end_time = datetime.now()
            training_time = (end_time - start_time).total_seconds()
            
            print(f"✅ Training completed in {training_time:.2f} seconds!")
            
            return True
            
        except Exception as e:
            print(f"❌ Error during training: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def evaluate_model(self):
        """Evaluate the trained model"""
        print("\n📊 MODEL EVALUATION")
        print("-"*70)
        
        try:
            # Predictions
            print("🔮 Making predictions...")
            y_pred = self.model.predict(self.X_test)
            
            # Accuracy
            accuracy = accuracy_score(self.y_test, y_pred)
            print(f"\n✅ Overall Accuracy: {accuracy*100:.2f}%")
            
            # Per-class metrics
            precision = precision_score(self.y_test, y_pred, average=None, zero_division=0)
            recall = recall_score(self.y_test, y_pred, average=None, zero_division=0)
            f1 = f1_score(self.y_test, y_pred, average=None, zero_division=0)
            
            print(f"\n📋 Per-Class Performance:")
            print(f"{'Class':<20} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
            print("-"*70)
            
            for i, label in enumerate(self.label_encoder.classes_):
                print(f"{label:<20} {precision[i]:>10.4f}  {recall[i]:>10.4f}  {f1[i]:>10.4f}")
            
            # Weighted averages
            precision_avg = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
            recall_avg = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
            f1_avg = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
            
            print("-"*70)
            print(f"{'WEIGHTED AVG':<20} {precision_avg:>10.4f}  {recall_avg:>10.4f}  {f1_avg:>10.4f}")
            
            # Confusion Matrix
            print(f"\n📊 Confusion Matrix:")
            cm = confusion_matrix(self.y_test, y_pred)
            
            # Display confusion matrix
            cm_df = pd.DataFrame(
                cm,
                index=[f"True {label}" for label in self.label_encoder.classes_],
                columns=[f"Pred {label}" for label in self.label_encoder.classes_]
            )
            print(cm_df)
            
            # Detailed classification report
            print(f"\n📋 Detailed Classification Report:")
            report = classification_report(
                self.y_test, y_pred,
                target_names=self.label_encoder.classes_,
                zero_division=0
            )
            print(report)
            
            # Save confusion matrix plot
            try:
                plt.figure(figsize=(10, 8))
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                           xticklabels=self.label_encoder.classes_,
                           yticklabels=self.label_encoder.classes_)
                plt.title('Confusion Matrix')
                plt.ylabel('True Label')
                plt.xlabel('Predicted Label')
                plt.tight_layout()
                plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
                print(f"\n📊 Confusion matrix saved to: confusion_matrix.png")
                plt.close()
            except Exception as e:
                print(f"⚠️  Could not save confusion matrix plot: {e}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error during evaluation: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def save_model(self, output_dir='.'):
        """Save the trained model and related objects"""
        print("\n💾 SAVING MODEL")
        print("-"*70)
        
        try:
            # Create output directory if needed
            os.makedirs(output_dir, exist_ok=True)
            
            # Save model
            model_file = os.path.join(output_dir, 'ids_model.pkl')
            joblib.dump(self.model, model_file)
            print(f"✅ Model saved to: {model_file}")
            
            # Save scaler
            scaler_file = os.path.join(output_dir, 'ids_scaler.pkl')
            joblib.dump(self.scaler, scaler_file)
            print(f"✅ Scaler saved to: {scaler_file}")
            
            # Save label encoder
            label_file = os.path.join(output_dir, 'ids_labels.pkl')
            joblib.dump(self.label_encoder, label_file)
            print(f"✅ Label encoder saved to: {label_file}")
            
            # Save feature names
            feature_names = self.df.drop('Label', axis=1).select_dtypes(include=[np.number]).columns.tolist()
            features_file = os.path.join(output_dir, 'ids_features.pkl')
            joblib.dump(feature_names, features_file)
            print(f"✅ Feature names saved to: {features_file}")
            
            # Save training metadata
            metadata = {
                'algorithm': self.model_name,
                'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'training_samples': len(self.X_train),
                'testing_samples': len(self.X_test),
                'num_features': self.X_train.shape[1],
                'classes': self.label_encoder.classes_.tolist(),
                'data_file': self.data_file
            }
            metadata_file = os.path.join(output_dir, 'ids_metadata.pkl')
            joblib.dump(metadata, metadata_file)
            print(f"✅ Metadata saved to: {metadata_file}")
            
            print(f"\n✅ All model files saved successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error saving model: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def feature_importance(self, top_n=20):
        """Display feature importance based on logistic regression coefficients"""
        try:
            if hasattr(self.model, 'coef_'):
                print("\n📊 FEATURE IMPORTANCE (Logistic Regression Coefficients)")
                print("-"*70)
                
                feature_names = self.df.drop('Label', axis=1).select_dtypes(include=[np.number]).columns
                importances = np.abs(self.model.coef_[0])
                
                # Create dataframe
                feat_imp_df = pd.DataFrame({
                    'Feature': feature_names,
                    'Importance': importances
                }).sort_values('Importance', ascending=False)
                
                print(f"\nTop {top_n} Most Important Features:")
                print(feat_imp_df.head(top_n).to_string(index=False))
                
                # Save plot
                try:
                    plt.figure(figsize=(10, 8))
                    feat_imp_df.head(top_n).plot(x='Feature', y='Importance', kind='barh')
                    plt.title(f'Top {top_n} Feature Importance (Logistic Regression)')
                    plt.xlabel('|Coefficient|')
                    plt.tight_layout()
                    plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
                    print(f"\n📊 Feature importance plot saved to: feature_importance.png")
                    plt.close()
                except Exception as e:
                    print(f"⚠️  Could not save feature importance plot: {e}")
                    
        except Exception as e:
            print(f"⚠️  Feature importance not available for this model type")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Train Network Intrusion Detection System Model',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--data',
                       default='collected_data.csv',
                       help='Input CSV file with collected data (default: collected_data.csv)')
    
    parser.add_argument('-a', '--algorithm',
                       choices=['logistic'],
                       default='logistic',
                       help='Machine learning algorithm (default: logistic)')
    
    parser.add_argument('-o', '--output',
                       default='.',
                       help='Output directory for model files (default: current directory)')
    
    parser.add_argument('--optimize',
                       action='store_true',
                       help='Perform hyperparameter optimization (slower but better results)')
    
    parser.add_argument('--no-plots',
                       action='store_true',
                       help='Skip generating plots')
    
    args = parser.parse_args()
    
    # Create trainer
    trainer = IDSTrainer(data_file=args.data)
    
    # Load data
    if not trainer.load_data():
        print("\n❌ Failed to load data. Exiting...")
        return 1
    
    # Preprocess
    if not trainer.preprocess_data():
        print("\n❌ Failed to preprocess data. Exiting...")
        return 1
    
    # Train
    if not trainer.train_model(algorithm=args.algorithm, optimize=args.optimize):
        print("\n❌ Failed to train model. Exiting...")
        return 1
    
    # Evaluate
    if not trainer.evaluate_model():
        print("\n❌ Failed to evaluate model. Exiting...")
        return 1
    
    # Feature importance
    if not args.no_plots:
        trainer.feature_importance()
    
    # Save
    if not trainer.save_model(output_dir=args.output):
        print("\n❌ Failed to save model. Exiting...")
        return 1
    
    print("\n" + "="*70)
    print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
    print("="*70)
    print("\nModel: Logistic Regression (Binary: BENIGN vs Attack)")
    print("\nNext steps:")
    print("1. Review the evaluation metrics above")
    print("2. Check confusion_matrix.png for visualization")
    print("3. Use Attack_Detector.py for real-time detection")
    print("="*70)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
