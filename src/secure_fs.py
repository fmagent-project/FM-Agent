import json
import os
import stat


class SecureFilesystemError(OSError):
    """Raised when an anchored filesystem operation cannot be completed safely."""


_SECURE_PRIMITIVES_AVAILABLE = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and all(
        function in os.supports_dir_fd
        for function in (os.open, os.mkdir, os.stat, os.unlink)
    )
)


def _require_secure_primitives():
    if not _SECURE_PRIMITIVES_AVAILABLE:
        raise SecureFilesystemError(
            "secure dir_fd filesystem operations are unavailable on this platform"
        )


def _relative_components(relative_path):
    path = os.fspath(relative_path)
    if not path or "\x00" in path or os.path.isabs(path):
        raise SecureFilesystemError(f"unsafe relative path: {relative_path}")
    normalized = os.path.normpath(path)
    components = normalized.split(os.sep)
    if normalized in {"", os.curdir} or any(
        component in {"", os.curdir, os.pardir} for component in components
    ):
        raise SecureFilesystemError(f"unsafe relative path: {relative_path}")
    return components


def _directory_flags():
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_root(root):
    _require_secure_primitives()
    root_path = os.path.abspath(os.fspath(root))
    try:
        descriptor = os.open(root_path, _directory_flags())
    except OSError as exc:
        raise SecureFilesystemError(f"unsafe filesystem root: {root_path}") from exc
    try:
        root_stat = os.fstat(descriptor)
    except Exception as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise SecureFilesystemError(
            f"cannot inspect filesystem root: {root_path}"
        ) from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(descriptor)
        raise SecureFilesystemError(f"filesystem root is not a directory: {root_path}")
    return root_path, descriptor


def _open_parent(root_descriptor, components, create):
    current = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            try:
                child = os.open(component, _directory_flags(), dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, _directory_flags(), dir_fd=current)
            except OSError as exc:
                raise SecureFilesystemError(
                    f"unsafe directory component: {component}"
                ) from exc
            os.close(current)
            current = child
        return current, components[-1]
    except Exception:
        os.close(current)
        raise


def _same_directory(left_stat, right_stat):
    return (
        left_stat.st_dev == right_stat.st_dev
        and left_stat.st_ino == right_stat.st_ino
    )


def _anchor_still_matches(root_path, root_descriptor, components, parent_descriptor):
    try:
        current_root = os.open(root_path, _directory_flags())
    except OSError:
        return False
    try:
        if not _same_directory(os.fstat(root_descriptor), os.fstat(current_root)):
            return False
        try:
            current_parent, _ = _open_parent(
                root_descriptor,
                components,
                create=False,
            )
        except (OSError, SecureFilesystemError):
            return False
        try:
            return _same_directory(
                os.fstat(parent_descriptor),
                os.fstat(current_parent),
            )
        finally:
            os.close(current_parent)
    finally:
        os.close(current_root)


def _lstat_at(parent_descriptor, basename):
    try:
        return os.stat(
            basename,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None


def _unlink_at(parent_descriptor, basename, missing_ok):
    try:
        os.unlink(basename, dir_fd=parent_descriptor)
        return True
    except FileNotFoundError:
        if missing_ok:
            return False
        raise


def atomic_write_json(root, relative_path, data):
    def write_json(stream):
        json.dump(data, stream, indent=2, ensure_ascii=False)

    _atomic_write(root, relative_path, write_json)


def atomic_write_text(root, relative_path, content):
    _atomic_write(root, relative_path, lambda stream: stream.write(content))


def _atomic_write(root, relative_path, writer):
    components = _relative_components(relative_path)
    root_path, root_descriptor = _open_root(root)
    parent_descriptor = None
    temp_basename = components[-1] + ".tmp"
    temp_created = False
    try:
        try:
            parent_descriptor, basename = _open_parent(
                root_descriptor,
                components,
                create=True,
            )
        except OSError as exc:
            raise SecureFilesystemError(
                f"cannot open artifact parent: {relative_path}"
            ) from exc

        temp_stat = _lstat_at(parent_descriptor, temp_basename)
        if temp_stat is not None:
            if not stat.S_ISREG(temp_stat.st_mode):
                raise SecureFilesystemError(
                    f"unsafe atomic-write temp path: {relative_path}.tmp"
                )
            _unlink_at(parent_descriptor, temp_basename, missing_ok=False)

        target_stat = _lstat_at(parent_descriptor, basename)
        if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
            raise SecureFilesystemError(f"unsafe artifact path: {relative_path}")

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(
                temp_basename,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise SecureFilesystemError(
                f"cannot create atomic-write temp: {relative_path}.tmp"
            ) from exc
        temp_created = True
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SecureFilesystemError(
                    f"atomic-write temp is not a regular file: {relative_path}.tmp"
                )
            with os.fdopen(descriptor, "w") as stream:
                descriptor = None
                writer(stream)
        finally:
            if descriptor is not None:
                os.close(descriptor)

        if not _anchor_still_matches(
            root_path,
            root_descriptor,
            components,
            parent_descriptor,
        ):
            raise SecureFilesystemError(
                f"artifact parent changed during write: {relative_path}"
            )

        target_stat = _lstat_at(parent_descriptor, basename)
        if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
            raise SecureFilesystemError(f"unsafe artifact path: {relative_path}")
        try:
            os.replace(
                temp_basename,
                basename,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        except (OSError, TypeError) as exc:
            raise SecureFilesystemError(
                f"cannot atomically replace artifact: {relative_path}"
            ) from exc
        temp_created = False

        if not _anchor_still_matches(
            root_path,
            root_descriptor,
            components,
            parent_descriptor,
        ):
            raise SecureFilesystemError(
                f"artifact parent changed during replace: {relative_path}"
            )
    finally:
        if temp_created and parent_descriptor is not None:
            try:
                _unlink_at(parent_descriptor, temp_basename, missing_ok=True)
            except OSError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        os.close(root_descriptor)


def load_json(root, relative_path):
    components = _relative_components(relative_path)
    root_path, root_descriptor = _open_root(root)
    parent_descriptor = None
    stream = None
    try:
        try:
            parent_descriptor, basename = _open_parent(
                root_descriptor,
                components,
                create=False,
            )

            def anchored_opener(_path, flags):
                return os.open(
                    basename,
                    flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_descriptor,
                )

            display_path = os.path.join(root_path, *components)
            stream = open(
                display_path,
                "r",
                opener=anchored_opener,
            )
        except OSError as exc:
            raise SecureFilesystemError(
                f"cannot safely open JSON artifact: {relative_path}"
            ) from exc
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise SecureFilesystemError(
                f"JSON artifact is not a regular file: {relative_path}"
            )
        value = json.load(stream)
        stream.close()
        stream = None
        if not _anchor_still_matches(
            root_path,
            root_descriptor,
            components,
            parent_descriptor,
        ):
            raise SecureFilesystemError(
                f"JSON artifact parent changed during read: {relative_path}"
            )
        return value
    finally:
        if stream is not None:
            stream.close()
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        os.close(root_descriptor)


def unlink(root, relative_path, *, missing_ok=False, allow_symlink=False):
    components = _relative_components(relative_path)
    root_path, root_descriptor = _open_root(root)
    parent_descriptor = None
    try:
        try:
            parent_descriptor, basename = _open_parent(
                root_descriptor,
                components,
                create=False,
            )
        except FileNotFoundError:
            if missing_ok:
                return False
            raise
        except OSError as exc:
            raise SecureFilesystemError(
                f"cannot safely open artifact parent: {relative_path}"
            ) from exc

        artifact_stat = _lstat_at(parent_descriptor, basename)
        if artifact_stat is None:
            if missing_ok:
                return False
            raise FileNotFoundError(relative_path)
        if not stat.S_ISREG(artifact_stat.st_mode) and not (
            allow_symlink and stat.S_ISLNK(artifact_stat.st_mode)
        ):
            raise SecureFilesystemError(f"unsafe artifact path: {relative_path}")
        if not _anchor_still_matches(
            root_path,
            root_descriptor,
            components,
            parent_descriptor,
        ):
            raise SecureFilesystemError(
                f"artifact parent changed before deletion: {relative_path}"
            )
        return _unlink_at(parent_descriptor, basename, missing_ok=missing_ok)
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        os.close(root_descriptor)
