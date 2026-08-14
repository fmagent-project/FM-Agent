struct Point {
    int x;
    int y;
};

enum Axis {
    AXIS_X,
    AXIS_Y
};

int select_coordinate(struct Point point, enum Axis axis) {
    return axis == AXIS_X ? point.x : point.y;
}
