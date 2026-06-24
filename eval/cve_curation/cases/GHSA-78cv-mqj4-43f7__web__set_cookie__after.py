    def set_cookie(
        self,
        name: str,
        value: Union[str, bytes],
        domain: Optional[str] = None,
        expires: Optional[Union[float, Tuple, datetime.datetime]] = None,
        path: str = "/",
        expires_days: Optional[float] = None,
        # Keyword-only args start here for historical reasons.
        *,
        max_age: Optional[int] = None,
        httponly: bool = False,
        secure: bool = False,
        samesite: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Sets an outgoing cookie name/value with the given options.

        Newly-set cookies are not immediately visible via `get_cookie`;
        they are not present until the next request.

        Most arguments are passed directly to `http.cookies.Morsel` directly.
        See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
        for more information.

        ``expires`` may be a numeric timestamp as returned by `time.time`,
        a time tuple as returned by `time.gmtime`, or a
        `datetime.datetime` object. ``expires_days`` is provided as a convenience
        to set an expiration time in days from today (if both are set, ``expires``
        is used).

        .. deprecated:: 6.3
           Keyword arguments are currently accepted case-insensitively.
           In Tornado 7.0 this will be changed to only accept lowercase
           arguments.
        """
        # The cookie library only accepts type str, in both python 2 and 3
        name = escape.native_str(name)
        value = escape.native_str(value)
        if re.search(r"[\x00-\x20]", value):
            # Legacy check for control characters in cookie values. This check is no longer needed
            # since the cookie library escapes these characters correctly now. It will be removed
            # in the next feature release.
            raise ValueError(f"Invalid cookie {name!r}: {value!r}")
        for attr_name, attr_value in [
            ("name", name),
            ("domain", domain),
            ("path", path),
            ("samesite", samesite),
        ]:
            # Cookie attributes may not contain control characters or semicolons (except when
            # escaped in the value). A check for control characters was added to the http.cookies
            # library in a Feb 2026 security release; as of March it still does not check for
            # semicolons.
            #
            # When a semicolon check is added to the standard library (and the release has had time
            # for adoption), this check may be removed, but be mindful of the fact that this may
            # change the timing of the exception (to the generation of the Set-Cookie header in
            # flush()). We m
            if attr_value is not None and re.search(r"[\x00-\x20\x3b\x7f]", attr_value):
                raise http.cookies.CookieError(
                    f"Invalid cookie attribute {attr_name}={attr_value!r} for cookie {name!r}"
                )
        if not hasattr(self, "_new_cookie"):
            self._new_cookie = (
                http.cookies.SimpleCookie()
            )  # type: http.cookies.SimpleCookie
        if name in self._new_cookie:
            del self._new_cookie[name]
        self._new_cookie[name] = value
        morsel = self._new_cookie[name]
        if domain:
            morsel["domain"] = domain
        if expires_days is not None and not expires:
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                days=expires_days
            )
        if expires:
            morsel["expires"] = httputil.format_timestamp(expires)
        if path:
            morsel["path"] = path
        if max_age:
            # Note change from _ to -.
            morsel["max-age"] = str(max_age)
        if httponly:
            # Note that SimpleCookie ignores the value here. The presense of an
            # httponly (or secure) key is treated as true.
            morsel["httponly"] = True
        if secure:
            morsel["secure"] = True
        if samesite:
            morsel["samesite"] = samesite
        if kwargs:
            # The setitem interface is case-insensitive, so continue to support
            # kwargs for backwards compatibility until we can remove deprecated
            # features.
            for k, v in kwargs.items():
                morsel[k] = v
            warnings.warn(
                f"Deprecated arguments to set_cookie: {set(kwargs.keys())} "
                "(should be lowercase)",
                DeprecationWarning,
            )
