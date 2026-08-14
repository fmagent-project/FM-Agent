int sum_positive(const int *values, int count) {
    int total = 0;
    for (int index = 0; index < count; ++index) {
        if (values[index] > 0) {
            total += values[index];
        }
    }
    return total;
}
