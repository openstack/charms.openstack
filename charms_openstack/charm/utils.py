import charmhelpers.fetch as fetch


# TODO: drop once charmhelpers releases a new version
#       with this function in the fetch helper (> 0.9.1)
def get_upstream_version(package):
    """Determine upstream version based on installed package

    @returns None (if not installed) or the upstream version
    """
    import apt_pkg
    cache = fetch.apt_cache()
    try:
        pkg = cache[package]
    except:
        # the package is unknown to the current apt cache.
        return None

    if not pkg.current_ver:
        # package is known, but no version is currently installed.
        return None

    return apt_pkg.upstream_version(pkg.current_ver.ver_str)
