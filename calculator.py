import math

def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

def divide(a, b):
    if b == 0:
        return "Error: Division by zero"
    return a / b

def power(a, b):
    return a ** b

def sqrt(a):
    if a < 0:
        return "Error: Cannot take square root of negative number"
    return math.sqrt(a)

def mod(a, b):
    if b == 0:
        return "Error: Division by zero"
    return a % b

def calculator():
    print("=" * 30)
    print("       Python Calculator")
    print("=" * 30)
    print("Supported operations:")
    print("1. Addition (+)")
    print("2. Subtraction (-)")
    print("3. Multiplication (*)")
    print("4. Division (/)")
    print("5. Power (^)")
    print("6. Square root (sqrt)")
    print("7. Modulo (%)")
    print("0. Exit")
    print("=" * 30)

    while True:
        choice = input("\nEnter operation number (0-7): ").strip()

        if choice == '0':
            print("Goodbye!")
            break

        if choice in ['1', '2', '3', '4', '5', '7']:
            try:
                a = float(input("Enter first number: "))
                b = float(input("Enter second number: "))

                if choice == '1':
                    result = add(a, b)
                    print(f"Result: {a} + {b} = {result}")
                elif choice == '2':
                    result = subtract(a, b)
                    print(f"Result: {a} - {b} = {result}")
                elif choice == '3':
                    result = multiply(a, b)
                    print(f"Result: {a} * {b} = {result}")
                elif choice == '4':
                    result = divide(a, b)
                    print(f"Result: {a} / {b} = {result}")
                elif choice == '5':
                    result = power(a, b)
                    print(f"Result: {a} ^ {b} = {result}")
                elif choice == '7':
                    result = mod(a, b)
                    print(f"Result: {a} % {b} = {result}")
            except ValueError:
                print("Error: Please enter valid numbers")

        elif choice == '6':
            try:
                a = float(input("Enter number: "))
                result = sqrt(a)
                print(f"Result: sqrt({a}) = {result}")
            except ValueError:
                print("Error: Please enter valid numbers")

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    calculator()
