@register.tag
@basictag(takes_context=True)
def gravatar(context, user, size=None):
    """
    Outputs the HTML for displaying a user's gravatar.

    This can take an optional size of the image (defaults to 80 if not
    specified).

    This is also influenced by the following settings:

        GRAVATAR_SIZE    - Default size for gravatars
        GRAVATAR_RATING  - Maximum allowed rating (g, pg, r, x)
        GRAVATAR_DEFAULT - Default image set to show if the user hasn't
                           specified a gravatar (identicon, monsterid, wavatar)

    See http://www.gravatar.com/ for more information.
    """
    url = get_gravatar_url(context['request'], user, size)

    if url:
        return format_html(
            '<img src="{0}" width="{1}" height="{1}" alt="{2}" '
            'class="gravatar"/>',
            url, size, user.get_full_name() or user.username)
    else:
        return ''
