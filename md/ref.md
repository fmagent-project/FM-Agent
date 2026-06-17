
# DUT Function Point and Check Point Description Guide

## Overview

This document explains how to perform functional analysis and check point definition for a DUT (Design Under Test). Through systematic functional grouping, function point identification, and check point design, it lays the foundation for subsequent functional coverage testing.

## Document Structure Hierarchy

Tag structures such as <FG-*> form a tree structure; child nodes under the same parent node must not share the same name.

### Hierarchy Relationships
```
DUT overall functionality
├── <FG-*> Functional group
│   ├── <FC-*> Function point 1
│   │   ├── <CK-*> Check point 1
│   │   ├── <CK-*> Check point 2
│   │   └── ...
│   ├── <FC-*> Function point 2
│   │   └── ...
│   └── ...
└── ...
```

### Tag System
- **Functional group tag**: `<FG-{group-name}>` - identifies a functional group
- **Function point tag**: `<FC-{function-name}>` - identifies a specific function point (also called a Test Point)
- **Check point tag**: `<CK-{check-point-name}>` - identifies a specific check point (also called a Test Bin, i.e. "test bin", "test interval", or "check point")

When "referencing" a check point (Test Bin), it is usually represented by joining the tags with '/':

- FG-{group-name}/FC-{function-name}/CK-{check-point-name}

For example:
- FG-GROUP-A/FC-FUNCTION-A1/CK-CHECK-A1-1
- FG-GROUP-A/FC-FUNCTION-A1/CK-CHECK-A1-2
- FG-ARITHMETIC/FC-ADD/CK-BASIC


**Important reminders**:
- The checker tool performs compliance checks based precisely on these tags, so the tag format must strictly follow the specification.
- Check points `<CK-{check-point-name}>` should be as independent as possible from each other; avoid cross-coverage of corresponding functionality, so that later bugs do not make coverage analysis difficult.

## Standard Document Format

### Document Template

```markdown
# {DUT Name} Function Point and Check Point Description

## DUT Overall Function Description

[Describe the overall functionality of the DUT here, including:]
- Main purpose and application scenarios
- Input/output interface description
- Key performance metrics
- Overview of the working principle

### Port Interface Description
- Input ports: [port name, bit width, function description]
- Output ports: [port name, bit width, function description]
- Control signals: [control signal description]

## Functional Groups and Check Points

### Functional Group A

<FG-GROUP-A>

[Overall description of the functional group, explaining the scope of functionality this group covers]

#### Specific Function A1

<FC-FUNCTION-A1>

[Describe in detail the specific implementation of function A1, its input/output relationships, expected behavior, etc.]

**Check points:**
- <CK-CHECK-A1-1> Check point 1: [specific check conditions and judgment criteria]
- <CK-CHECK-A1-2> Check point 2: [specific check conditions and judgment criteria]
- ...

#### Specific Function A2

<FC-FUNCTION-A2>

[Description of function A2...]

**Check points:**
- <CK-CHECK-A2-1> Check point 1: [check conditions...]
- ...

### Functional Group B

<FG-GROUP-B>

[Continue with the next functional group...]
```

### Tag Placement Conventions

**✅ Correct tag placement**
```markdown
### Specific Function 1

<FC-FUNC1>

Function description content...
```

**❌ Incorrect tag placement**
```markdown
### Specific Function 1 <FC-FUNC1>
Function description content...
```

Tags should be placed on their own line, separated from the heading by a blank line, to avoid being visible in the Markdown preview.

## Naming Conventions and Best Practices

### Naming Principles

1. **Conciseness**: Names should be short but have clear meaning
2. **Consistency**: Use a unified naming pattern for similar functions
3. **Readability**: Names should be easy to understand; avoid ambiguous abbreviations
4. **Hierarchy**: Reflect the hierarchical relationships of the functionality

### Recommended Naming Patterns

#### Functional Group Naming
```markdown
<FG-ARITHMETIC>    # Arithmetic operation group
<FG-LOGIC>         # Logic operation group  
<FG-MEMORY>        # Memory operation group
<FG-CONTROL>       # Control function group
<FG-IO>            # Input/output group
```

#### Function Point Naming
```markdown
<FC-ADD>           # Addition function
<FC-SUB>           # Subtraction function
<FC-MUL>           # Multiplication function
<FC-CACHE-READ>    # Cache read
<FC-CACHE-WRITE>   # Cache write
<FC-BRANCH-PRED>   # Branch prediction
```

#### Check Point Naming
```markdown
<CK-NORM>          # Normal case
<CK-OVERFLOW>      # Overflow case
<CK-BOUNDARY>      # Boundary condition
<CK-ERROR>         # Error condition
<CK-ZERO>          # Zero-value handling
<CK-MAX>           # Maximum-value handling
<CK-MIN>           # Minimum-value handling
```

#### Required Groups

In all function point and check point description documents, the following group must be present:

<FG-API> # Test API group, the standard APIs needed for verifying the DUT

## Complete Example: ALU Design

### Design Specification

```markdown
# ALU Function Point and Check Point Description

## DUT Overall Function Description

The ALU (Arithmetic Logic Unit) is a core component of the CPU, responsible for performing various arithmetic and logic operations. This ALU supports 64-bit data processing and provides multiple operation modes.

### Port Interface Description

**Input ports:**
- `a`: First operand, 64-bit unsigned number
- `b`: Second operand, 64-bit unsigned number  
- `cin`: Carry/borrow input, 1 bit
- `op`: Function select signal, 4 bits, used to select the operation type

**Output ports:**
- `out`: Operation result, 64 bits
- `cout`: Carry, borrow, or overflow flag, 1 bit

**Control interface:**
- `enable`: Enable signal, 1 bit
- `reset`: Reset signal, 1 bit, active high

### Operation Mode Definitions

| op value | Operation type | Operation formula | Meaning of cout |
|------|----------|----------|----------|
| 0    | Addition     | {cout,out} = a + b + cin | Carry output |
| 1    | Subtraction     | out = a - b - cin | Borrow flag |
| 2    | Multiplication     | out = a × b | Overflow flag |
| 3    | Bitwise AND   | out = a & b | Fixed to 0 |
| 4    | Bitwise OR   | out = a \| b | Fixed to 0 |
| 5    | Bitwise XOR | out = a ^ b | Fixed to 0 |
| 6    | Bitwise NOT   | out = ~a | Fixed to 0 |
| 7    | Left shift     | out = a << (b & 0x3F) | Fixed to 0 |
| 8    | Right shift     | out = a >> (b & 0x3F) | Fixed to 0 |
| Other | Reserved     | out = 0, cout = 0 | Undefined |

## Functional Groups and Check Points


### DUT Test API

<FG-API>

#### General operation function

<FC-OPERATION>

Provides interfaces for the various operations supported by the DUT, covering the operation types corresponding to all op opcodes. These operations are the core function implementation of the DUT.

**Check points:**
- <CK-ADD> Addition operation: verify the addition function when op=0, {cout,out} = a + b + cin
- <CK-SUB> Subtraction operation: verify the subtraction function when op=1, out = a - b - cin  
- <CK-MUL> Multiplication operation: verify the multiplication function when op=2, out = a × b
- <CK-AND> Bitwise AND operation: verify the bitwise AND function when op=3, out = a & b
- <CK-OR> Bitwise OR operation: verify the bitwise OR function when op=4, out = a | b
- <CK-XOR> Bitwise XOR operation: verify the bitwise XOR function when op=5, out = a ^ b
- <CK-NOT> Bitwise NOT operation: verify the bitwise NOT function when op=6, out = ~a
- <CK-SHL> Left shift operation: verify the left shift function when op=7, out = a << (b & 0x3F)
- <CK-SHR> Right shift operation: verify the right shift function when op=8, out = a >> (b & 0x3F)
- <CK-INVALID> Invalid opcode: verify the handling when op value is out of the defined range, out = 0


<FG-ARITHMETIC>

### Arithmetic Operation Functional Group
Contains basic arithmetic operation functions: addition, subtraction, multiplication, etc.

#### Addition Function

<FC-ADD>

Implements 64-bit addition, supporting carry input. Operation formula: {cout, out} = a + b + cin

**Check points:**
- <CK-BASIC> Basic addition: verify basic addition without carry input, e.g. 1+1=2
- <CK-CARRY-IN> Carry input: verify addition with carry input, e.g. 1+1+1=3  
- <CK-OVERFLOW> Addition overflow: verify the correctness of the carry output when the result exceeds 64 bits
- <CK-ZERO> Zero-value operation: verify the correctness when an operand is 0, e.g. 0+0=0
- <CK-BOUNDARY> Boundary conditions: verify operations under boundary conditions such as maximum and minimum values

#### Subtraction Function

<FC-SUB>

Implements 64-bit subtraction, supporting borrow input. Operation formula: out = a - b - cin

**Check points:**
- <CK-BASIC> Basic subtraction: verify basic subtraction without borrow input, e.g. 5-3=2
- <CK-BORROW-IN> Borrow input: verify subtraction with borrow input
- <CK-UNDERFLOW> Subtraction underflow: verify the correctness of the borrow output when a<b
- <CK-ZERO-RESULT> Zero result: verify the case where the result is 0 when a=b
- <CK-SELF-SUB> Self-subtraction: verify the special case a-a=0

#### Multiplication Function

<FC-MUL>

Implements 64-bit multiplication. When the result exceeds 64 bits, cout indicates overflow.

**Check points:**
- <CK-BASIC> Basic multiplication: verify basic multiplication, e.g. 2×3=6
- <CK-OVERFLOW> Multiplication overflow: verify the correctness of the overflow flag when the result exceeds 64 bits
- <CK-ZERO-FACTOR> Zero factor: verify that the result is 0 when an operand is 0
- <CK-ONE-FACTOR> Unit factor: verify that the result is unchanged when multiplying by 1
- <CK-LARGE-NUM> Large-number multiplication: verify the correctness of multiplying large numbers

<FG-LOGIC>

### Logic Operation Functional Group
Contains various bit operation and logic operation functions.

#### Bit Operation Function

<FC-BITWISE>

Implements basic bit operations: AND, OR, XOR, NOT, etc.

**Check points:**
- <CK-AND> Bitwise AND: verify the correctness of the a&b operation
- <CK-OR> Bitwise OR: verify the correctness of the a|b operation
- <CK-XOR> Bitwise XOR: verify the correctness of the a^b operation
- <CK-NOT> Bitwise NOT: verify the correctness of the ~a operation (b is invalid)
- <CK-ALL-ONES> All-ones operation: verify the result when the operand is all 1s
- <CK-ALL-ZEROS> All-zeros operation: verify the result when the operand is all 0s

#### Shift Function

<FC-SHIFT>

Implements left and right shift operations, with the shift amount taken from the low 6 bits of b.

**Check points:**
- <CK-SHL-BASIC> Basic left shift: verify the correctness of basic left shift operation
- <CK-SHR-BASIC> Basic right shift: verify the correctness of basic right shift operation
- <CK-SHIFT-ZERO> Zero shift: verify that the result is unchanged when the shift amount is 0
- <CK-SHIFT-MAX> Maximum shift: verify the result when shifting by 63 bits
- <CK-SHIFT-OVERFLOW> Shift overflow: verify the behavior when the shift amount ≥ 64

<FG-CONTROL>

### Control Functional Group
Contains control signal handling and special state management.

#### Enable Control

<FC-ENABLE>

Controls the enable state of the ALU; when the enable signal is invalid, the output is held.

**Check points:**
- <CK-ENABLE-HIGH> Enable active: verify normal operation when the enable signal is active
- <CK-ENABLE-LOW> Enable inactive: verify that the output remains unchanged when the enable signal is inactive
- <CK-ENABLE-TOGGLE> Enable toggle: verify the behavior when the enable signal toggles

#### Reset Function

<FC-RESET>

Handles the reset signal; on reset, all outputs are cleared to zero.

**Check points:**
- <CK-RESET-SYNC> Synchronous reset: verify the correctness of synchronous reset
- <CK-RESET-ASYNC> Asynchronous reset: verify the correctness of asynchronous reset (if supported)
- <CK-RESET-RELEASE> Reset release: verify normal operation after reset is released

#### Undefined Operation

<FC-UNDEFINED>

Handles undefined opcodes to ensure predictable output.

**Check points:**
- <CK-OP-INVALID> Invalid opcode: verify that the output is 0 when the op value is out of the defined range
- <CK-OP-RESERVED> Reserved opcode: verify the handling of reserved opcodes
```

## Quality Checklist

### Completeness Check
- [ ] Each functional group contains at least one function point
- [ ] Each function point contains at least one check point  
- [ ] All tag formats are correct and unique
- [ ] Function descriptions are clear and complete

### Consistency Check
- [ ] Naming style is consistent
- [ ] Tag placement is correct
- [ ] Check points cover the main scenarios
- [ ] No duplication or omission between function points

### Testability Check
- [ ] Check points can be verified through test cases
- [ ] Check conditions are clear and decidable
- [ ] Boundary conditions and exceptional cases have been considered
- [ ] Test data can be designed
