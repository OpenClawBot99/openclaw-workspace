#!/usr/bin/env python3
"""
Compute the first 10 Fibonacci numbers.
Usage: python fib.py
"""

def fibonacci(n):
    """Return the first n Fibonacci numbers as a list."""
    if n <= 0:
        return []
    seq = [0, 1]
    while len(seq) < n:
        seq.append(seq[-1] + seq[-2])
    return seq[:n]

def main():
    n = 10
    fibs = fibonacci(n)
    print(" ".join(map(str, fibs)))

if __name__ == "__main__":
    main()
