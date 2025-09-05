#!/usr/bin/env python3

import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import argparse

def plot_memory_data(csv_file, output_prefix=None):
    """Plot memory metrics from CSV data"""
    
    try:
        # Read CSV data
        df = pd.read_csv(csv_file)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        if output_prefix is None:
            output_prefix = csv_file.replace('.csv', '')
        
        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('golubsmtpd Memory Performance Over Time', fontsize=16, fontweight='bold')
        
        # Plot 1: Heap Allocation
        ax1.plot(df['timestamp'], df['heap_alloc_mb'], color='red', linewidth=2, label='Heap Alloc')
        ax1.plot(df['timestamp'], df['heap_inuse_mb'], color='orange', linewidth=2, label='Heap InUse')
        ax1.set_ylabel('Memory (MB)')
        ax1.set_title('Heap Memory Usage')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
        
        # Plot 2: Heap Objects
        ax2.plot(df['timestamp'], df['heap_objects'], color='blue', linewidth=2)
        ax2.set_ylabel('Object Count')
        ax2.set_title('Heap Objects')
        ax2.grid(True, alpha=0.3)
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)
        
        # Plot 3: Goroutines
        ax3.plot(df['timestamp'], df['goroutines'], color='green', linewidth=2)
        ax3.set_ylabel('Goroutine Count')
        ax3.set_title('Active Goroutines')
        ax3.grid(True, alpha=0.3)
        ax3.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45)
        
        # Plot 4: GC Cycles
        ax4.plot(df['timestamp'], df['gc_cycles'], color='purple', linewidth=2)
        ax4.set_ylabel('GC Cycle Count')
        ax4.set_title('Garbage Collection Cycles')
        ax4.grid(True, alpha=0.3)
        ax4.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45)
        
        plt.tight_layout()
        
        # Save plot
        output_file = f"{output_prefix}_plot.png"
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"📊 Plot saved to: {output_file}")
        
        # Show summary statistics
        print("\n📈 Memory Statistics Summary:")
        print(f"Peak Heap Alloc: {df['heap_alloc_mb'].max():.2f} MB")
        print(f"Min Heap Alloc: {df['heap_alloc_mb'].min():.2f} MB")
        print(f"Avg Heap Alloc: {df['heap_alloc_mb'].mean():.2f} MB")
        print(f"Peak Objects: {int(df['heap_objects'].max()):,}")
        print(f"Peak Goroutines: {int(df['goroutines'].max())}")
        print(f"Total GC Cycles: {int(df['gc_cycles'].iloc[-1] - df['gc_cycles'].iloc[0])}")
        
        return output_file
        
    except Exception as e:
        print(f"❌ Error plotting data: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Plot golubsmtpd memory metrics')
    parser.add_argument('csv_file', help='CSV file containing memory data')
    parser.add_argument('--output', '-o', help='Output file prefix')
    parser.add_argument('--show', '-s', action='store_true', help='Show plot interactively')
    
    args = parser.parse_args()
    
    if not args.csv_file:
        print("Usage: python3 plot_memory.py <csv_file>")
        sys.exit(1)
    
    output_file = plot_memory_data(args.csv_file, args.output)
    
    if output_file and args.show:
        plt.show()

if __name__ == "__main__":
    main()