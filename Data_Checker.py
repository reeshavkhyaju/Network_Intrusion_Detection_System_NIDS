#!/usr/bin/python3
"""
Data Quality Checker
Verifies collected network traffic data for binary IDS training (BENIGN vs Attack)
"""

import pandas as pd
import numpy as np
import argparse
import os
import sys

def check_data_quality(csv_file):
    """Analyze collected data quality"""
    
    print("\n" + "="*70)
    print("📊 DATA QUALITY ANALYSIS")
    print("="*70)
    
    if not os.path.exists(csv_file):
        print(f"\n❌ Error: File '{csv_file}' not found!")
        return
    
    try:
        # Load data
        print(f"\n📂 Loading data from: {csv_file}")
        df = pd.read_csv(csv_file)
        
        # Basic statistics
        print(f"\n✅ File loaded successfully!")
        print(f"   Total rows: {len(df):,}")
        print(f"   Total columns: {len(df.columns)}")
        print(f"   File size: {os.path.getsize(csv_file) / (1024*1024):.2f} MB")
        
        # Check for Label column
        if 'Label' not in df.columns:
            print("\n❌ Error: 'Label' column not found!")
            print("   Available columns:", list(df.columns))
            return
        
        # Label distribution
        print("\n" + "-"*70)
        print("📋 LABEL DISTRIBUTION")
        print("-"*70)
        
        label_counts = df['Label'].value_counts()
        total = len(df)
        
        print(f"\n{'Label':<20} {'Count':<15} {'Percentage':<15} {'Status'}")
        print("-"*70)
        
        for label, count in label_counts.items():
            percentage = (count / total) * 100
            
            # Status indicator
            if count < 1000:
                status = "⚠️  Low (Need more)"
            elif count < 5000:
                status = "✓ Good"
            else:
                status = "✓✓ Excellent"
            
            print(f"{label:<20} {count:<15,} {percentage:>6.2f}%        {status}")
        
        print("-"*70)
        print(f"{'TOTAL':<20} {total:<15,} {100.0:>6.2f}%")
        
        # Missing values check
        print("\n" + "-"*70)
        print("🔍 MISSING VALUES CHECK")
        print("-"*70)
        
        missing = df.isnull().sum()
        if missing.sum() == 0:
            print("\n✅ No missing values found!")
        else:
            print("\n⚠️  Missing values detected:")
            for col in missing[missing > 0].index:
                print(f"   {col}: {missing[col]} ({missing[col]/len(df)*100:.2f}%)")
        
        # Infinite values check
        print("\n" + "-"*70)
        print("🔍 INFINITE VALUES CHECK")
        print("-"*70)
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        inf_counts = {}
        for col in numeric_cols:
            inf_count = np.isinf(df[col]).sum()
            if inf_count > 0:
                inf_counts[col] = inf_count
        
        if len(inf_counts) == 0:
            print("\n✅ No infinite values found!")
        else:
            print("\n⚠️  Infinite values detected:")
            for col, count in inf_counts.items():
                print(f"   {col}: {count}")
        
        # Feature statistics
        print("\n" + "-"*70)
        print("📈 KEY FEATURE STATISTICS")
        print("-"*70)
        
        key_features = [
            'Flow Duration',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Flow Bytes/s',
            'Flow Packets/s',
            'SYN Flag Count',
            'ACK Flag Count'
        ]
        
        print(f"\n{'Feature':<30} {'Min':<15} {'Max':<15} {'Mean':<15}")
        print("-"*70)
        
        for feature in key_features:
            if feature in df.columns:
                col_data = df[feature]
                print(f"{feature:<30} {col_data.min():<15.2f} "
                      f"{col_data.max():<15.2f} {col_data.mean():<15.2f}")
        
        # Check for suspicious patterns
        print("\n" + "-"*70)
        print("🔍 SUSPICIOUS PATTERNS CHECK")
        print("-"*70)
        
        suspicious = []
        
        # Check for flows with 0 duration but packets
        zero_duration = df[(df['Flow Duration'] == 0) & 
                          ((df['Total Fwd Packets'] > 0) | 
                           (df['Total Backward Packets'] > 0))]
        if len(zero_duration) > 0:
            suspicious.append(f"⚠️  {len(zero_duration)} flows with 0 duration but packets")
        
        # Check for flows with no packets
        no_packets = df[(df['Total Fwd Packets'] == 0) & 
                       (df['Total Backward Packets'] == 0)]
        if len(no_packets) > 0:
            suspicious.append(f"⚠️  {len(no_packets)} flows with no packets")
        
        # Check for extremely high packet rates
        high_rate = df[df['Flow Packets/s'] > 1000000]
        if len(high_rate) > 0:
            suspicious.append(f"⚠️  {len(high_rate)} flows with extremely high packet rate")
        
        if len(suspicious) == 0:
            print("\n✅ No suspicious patterns detected!")
        else:
            print()
            for pattern in suspicious:
                print(f"   {pattern}")
        
        # Recommendations
        print("\n" + "="*70)
        print("💡 RECOMMENDATIONS")
        print("="*70)
        
        recommendations = []
        
        for label in ['BENIGN', 'Attack']:
            if label not in label_counts:
                recommendations.append(f"\u2757 Missing '{label}' samples - collect this traffic type")
            elif label_counts[label] < 1000:
                recommendations.append(f"\u26a0\ufe0f  Only {label_counts[label]} '{label}' samples - "
                                     f"collect at least {1000 - label_counts[label]} more")
        
        # Check balance
        if len(label_counts) > 1:
            max_count = label_counts.max()
            min_count = label_counts.min()
            imbalance_ratio = max_count / min_count
            
            if imbalance_ratio > 5:
                recommendations.append(f"⚠️  Dataset is imbalanced (ratio: {imbalance_ratio:.1f}:1) - "
                                     "collect more samples of underrepresented classes")
        
        if len(recommendations) == 0:
            print("\n✅ Dataset looks good! Ready for training.")
        else:
            print()
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. {rec}")
        
        # Save summary
        print("\n" + "="*70)
        
        summary_file = csv_file.replace('.csv', '_summary.txt')
        with open(summary_file, 'w') as f:
            f.write("DATA QUALITY SUMMARY\n")
            f.write("="*70 + "\n\n")
            f.write(f"File: {csv_file}\n")
            f.write(f"Total samples: {total:,}\n")
            f.write(f"Total features: {len(df.columns)}\n\n")
            f.write("Label Distribution:\n")
            for label, count in label_counts.items():
                f.write(f"  {label}: {count:,} ({count/total*100:.2f}%)\n")
        
        print(f"📄 Summary saved to: {summary_file}")
        
    except Exception as e:
        print(f"\n❌ Error analyzing data: {e}")
        import traceback
        traceback.print_exc()


def compare_with_cicids2017():
    """Show CICIDS2017 feature list for comparison"""
    
    print("\n" + "="*70)
    print("📋 CICIDS2017 REQUIRED FEATURES")
    print("="*70)
    
    required_features = [
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Fwd IAT Mean',
        'Bwd IAT Mean',
        'Fwd PSH Flags',
        'Bwd PSH Flags',
        'Fwd URG Flags',
        'Bwd URG Flags',
        'FIN Flag Count',
        'SYN Flag Count',
        'RST Flag Count',
        'PSH Flag Count',
        'ACK Flag Count',
        'URG Flag Count',
        'Down/Up Ratio',
        'Average Packet Size',
        'Fwd Segment Size Avg',
        'Bwd Segment Size Avg',
        'Subflow Fwd Packets',
        'Subflow Fwd Bytes',
        'Subflow Bwd Packets',
        'Subflow Bwd Bytes',
        'Init_Win_bytes_forward',
        'Init_Win_bytes_backward',
        'Label'
    ]
    
    print(f"\nTotal required features: {len(required_features)}")
    print("\nFeature list:")
    for i, feature in enumerate(required_features, 1):
        print(f"  {i:2}. {feature}")


def merge_csv_files(input_files, output_file):
    """Merge multiple CSV files"""
    
    print("\n" + "="*70)
    print("🔗 MERGING CSV FILES")
    print("="*70)
    
    try:
        dfs = []
        total_rows = 0
        
        for file in input_files:
            if os.path.exists(file):
                df = pd.read_csv(file)
                dfs.append(df)
                total_rows += len(df)
                print(f"✓ Loaded {file}: {len(df):,} rows")
            else:
                print(f"✗ File not found: {file}")
        
        if len(dfs) == 0:
            print("\n❌ No files to merge!")
            return
        
        # Merge
        merged_df = pd.concat(dfs, ignore_index=True)
        
        # Save
        merged_df.to_csv(output_file, index=False)
        
        print(f"\n✅ Successfully merged {len(dfs)} files")
        print(f"   Total rows: {total_rows:,}")
        print(f"   Output file: {output_file}")
        print(f"   File size: {os.path.getsize(output_file) / (1024*1024):.2f} MB")
        
        # Show label distribution
        print(f"\nLabel distribution in merged file:")
        label_counts = merged_df['Label'].value_counts()
        for label, count in label_counts.items():
            print(f"   {label}: {count:,} ({count/len(merged_df)*100:.2f}%)")
        
    except Exception as e:
        print(f"\n❌ Error merging files: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Network Traffic Data Quality Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('csv_file',
                       nargs='?',
                       help='CSV file to analyze')
    
    parser.add_argument('--features',
                       action='store_true',
                       help='Show required CICIDS2017 features')
    
    parser.add_argument('--merge',
                       nargs='+',
                       metavar='FILE',
                       help='Merge multiple CSV files')
    
    parser.add_argument('-o', '--output',
                       default='merged_data.csv',
                       help='Output file for merge (default: merged_data.csv)')
    
    args = parser.parse_args()
    
    if args.features:
        compare_with_cicids2017()
    
    elif args.merge:
        merge_csv_files(args.merge, args.output)
        print("\n" + "="*70)
        print("Analyzing merged file...")
        check_data_quality(args.output)
    
    elif args.csv_file:
        check_data_quality(args.csv_file)
    
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python Data_Checker.py collected_data.csv")
        print("  python Data_Checker.py --features")
        print("  python Data_Checker.py --merge file1.csv file2.csv file3.csv -o final_data.csv")


if __name__ == "__main__":
    main()
