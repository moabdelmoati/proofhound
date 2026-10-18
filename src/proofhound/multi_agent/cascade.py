"""Small model first; escalate to the large model when the check fails or confidence is low.

Where execution can verify the result (Harness, Patcher), execution is the judge.
Where it cannot (Triage, Analyzer filter), the large model reviews.
"""
