typedef int (*operation)(int, int);

static int multiply(int left, int right) {
    return left * right;
}

int apply(operation op, int left, int right) {
    return op(left, right);
}

int main(void) {
    return apply(multiply, 3, 4) == 12 ? 0 : 1;
}
