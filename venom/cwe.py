CWE_DATABASE = {
    78: {
        "id": 78, "name": "OS Command Injection",
        "description": "The product constructs an OS command using externally-influenced input without neutralizing special elements.",
        "severity": "critical", "category": "injection",
    },
    119: {
        "id": 119, "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "description": "The product performs operations on a memory buffer without properly restricting reads/writes to the buffer boundaries.",
        "severity": "high", "category": "memory-safety",
    },
    120: {
        "id": 120, "name": "Buffer Copy without Checking Size of Input",
        "description": "The program copies input to a buffer without checking that the size of the input is within the buffer bounds.",
        "severity": "critical", "category": "memory-safety",
    },
    121: {
        "id": 121, "name": "Stack-based Buffer Overflow",
        "description": "A stack-based buffer overflow overwrites data on the stack, potentially altering control flow.",
        "severity": "critical", "category": "memory-safety",
    },
    122: {
        "id": 122, "name": "Heap-based Buffer Overflow",
        "description": "A heap-based buffer overflow condition overwrites heap-allocated data.",
        "severity": "critical", "category": "memory-safety",
    },
    125: {
        "id": 125, "name": "Out-of-bounds Read",
        "description": "The product reads data past the end or before the beginning of the intended buffer.",
        "severity": "high", "category": "memory-safety",
    },
    134: {
        "id": 134, "name": "Use of Externally-Controlled Format String",
        "description": "The product uses a function that accepts a format string as an argument from an external source.",
        "severity": "critical", "category": "injection",
    },
    190: {
        "id": 190, "name": "Integer Overflow or Wraparound",
        "description": "The product performs arithmetic that can produce an integer overflow or wraparound.",
        "severity": "high", "category": "integer-error",
    },
    191: {
        "id": 191, "name": "Integer Underflow",
        "description": "The product subtracts values that produce a result smaller than the minimum representable value.",
        "severity": "high", "category": "integer-error",
    },
    369: {
        "id": 369, "name": "Divide By Zero",
        "description": "The product divides a value by zero.",
        "severity": "medium", "category": "integer-error",
    },
    362: {
        "id": 362, "name": "Concurrent Execution Using Shared Resource with Improper Synchronization",
        "description": "The product contains a concurrent code sequence that requires exclusive access to a shared resource but does not ensure it.",
        "severity": "high", "category": "race-condition",
    },
    401: {
        "id": 401, "name": "Missing Release of Memory after Effective Lifetime",
        "description": "The product does not sufficiently release allocated memory after use, causing memory leaks.",
        "severity": "medium", "category": "memory-safety",
    },
    415: {
        "id": 415, "name": "Double Free",
        "description": "The product calls free() twice on the same memory address, potentially leading to corruption.",
        "severity": "critical", "category": "memory-safety",
    },
    416: {
        "id": 416, "name": "Use After Free",
        "description": "The product references memory after it has been freed, which can lead to corruption or code execution.",
        "severity": "critical", "category": "memory-safety",
    },
    457: {
        "id": 457, "name": "Use of Uninitialized Variable",
        "description": "The code uses a variable that has not been initialized, leading to unpredictable behavior.",
        "severity": "medium", "category": "memory-safety",
    },
    476: {
        "id": 476, "name": "NULL Pointer Dereference",
        "description": "The product dereferences a pointer that it expects to be valid but is NULL.",
        "severity": "high", "category": "memory-safety",
    },
    667: {
        "id": 667, "name": "Improper Locking",
        "description": "The product does not properly acquire or release a lock on a resource.",
        "severity": "medium", "category": "race-condition",
    },
    770: {
        "id": 770, "name": "Allocation of Resources Without Limits or Throttling",
        "description": "The product allocates resources without an effective limit, leading to exhaustion.",
        "severity": "medium", "category": "resource-exhaustion",
    },
    787: {
        "id": 787, "name": "Out-of-bounds Write",
        "description": "The product writes data past the end or before the beginning of the intended buffer.",
        "severity": "critical", "category": "memory-safety",
    },
    126: {
        "id": 126, "name": "Buffer Over-read",
        "description": "The product reads from a buffer using an index or pointer past the bounds of the buffer.",
        "severity": "high", "category": "memory-safety",
    },
    127: {
        "id": 127, "name": "Buffer Under-read",
        "description": "The product reads from a buffer using a negative index or pointer before the buffer start.",
        "severity": "high", "category": "memory-safety",
    },
    131: {
        "id": 131, "name": "Incorrect Calculation of Buffer Size",
        "description": "The product does not correctly calculate the size needed for a buffer, leading to overflows.",
        "severity": "high", "category": "memory-safety",
    },
    170: {
        "id": 170, "name": "Improper Null Termination",
        "description": "The product does not properly null-terminate a string or string-like data structure.",
        "severity": "medium", "category": "memory-safety",
    },
    252: {
        "id": 252, "name": "Unchecked Return Value",
        "description": "The product does not check the return value from a function, missing error conditions.",
        "severity": "low", "category": "error-handling",
    },
    681: {
        "id": 681, "name": "Incorrect Conversion between Numeric Types",
        "description": "When converting between numeric types, the product does not handle boundary cases.",
        "severity": "medium", "category": "integer-error",
    },
    129: {
        "id": 129, "name": "Improper Validation of Array Index",
        "description": "The product uses untrusted input when calculating or using an array index.",
        "severity": "high", "category": "memory-safety",
    },
    467: {
        "id": 467, "name": "Use of sizeof() on a Pointer Type",
        "description": "The code calls sizeof() on a pointer type incorrectly, expecting the buffer size.",
        "severity": "medium", "category": "memory-safety",
    },
    561: {
        "id": 561, "name": "Dead Code",
        "description": "The product contains code that will never be executed (dead store or unreachable).",
        "severity": "low", "category": "code-quality",
    },
    562: {
        "id": 562, "name": "Return of Stack Variable Address",
        "description": "A function returns the address of a stack variable, which becomes invalid after return.",
        "severity": "high", "category": "memory-safety",
    },
    563: {
        "id": 563, "name": "Assignment to Variable without Use",
        "description": "The variable's value is assigned but never used, indicating dead code or a logic error.",
        "severity": "low", "category": "code-quality",
    },
    682: {
        "id": 682, "name": "Incorrect Calculation",
        "description": "The product performs a calculation that generates incorrect or unintended results.",
        "severity": "medium", "category": "integer-error",
    },
    775: {
        "id": 775, "name": "Missing Release of File Descriptor or Handle after Effective Lifetime",
        "description": "The product does not release a file descriptor or handle after use, causing resource leak.",
        "severity": "medium", "category": "resource-exhaustion",
    },
    823: {
        "id": 823, "name": "Use of Out-of-range Pointer Offset",
        "description": "The product performs pointer arithmetic that results in an out-of-range pointer.",
        "severity": "high", "category": "memory-safety",
    },
}

SEVERITY_SCORE = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
}

CATEGORY_DISPLAY = {
    "memory-safety": "Memory Safety",
    "integer-error": "Integer Error",
    "injection": "Injection",
    "race-condition": "Race Condition",
    "resource-exhaustion": "Resource Exhaustion",
    "error-handling": "Error Handling",
    "code-quality": "Code Quality",
}

_UNKNOWN_CWE = {
    "id": 0, "name": "Unknown",
    "description": "CWE not catalogued in local database.",
    "severity": "medium", "category": "unknown",
}


def get_cwe(cwe_id):
    cwe_id = int(cwe_id) if cwe_id else 0
    return CWE_DATABASE.get(cwe_id, {**_UNKNOWN_CWE, "id": cwe_id})


def get_severity(cwe_id):
    return get_cwe(cwe_id)["severity"]


def severity_score(severity):
    return SEVERITY_SCORE.get(severity, 0.3)
