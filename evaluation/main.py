"""Evaluation runner: executes score_samples and coverage audits."""
import subprocess
import sys
import os

def run():
    eval_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(os.path.dirname(eval_dir))
    
    print("=" * 60)
    print("RUNNING SAMPLE BENCHMARK (score_samples.py)")
    print("=" * 60)
    subprocess.run([sys.executable, os.path.join(eval_dir, "score_samples.py")], cwd=root_dir, check=True)
    
    print("\n" + "=" * 60)
    print("RUNNING CLUSTER COVERAGE AUDIT (coverage.py)")
    print("=" * 60)
    subprocess.run([sys.executable, os.path.join(eval_dir, "coverage.py")], cwd=root_dir, check=True)

if __name__ == "__main__":
    run()
